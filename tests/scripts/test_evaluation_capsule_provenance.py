from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
from datetime import date
from pathlib import Path

import pytest

from regulatory_harvest.evaluation import attorney_generation
from regulatory_harvest.evaluation.attorney_artifacts import _load_model_bytes
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    BlindAssignment,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    EvaluationSourceParityUnprovenError,
    initialize_evaluation,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
FULL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
RUNNERS = (FULL_RUNNER, PORTABLE_RUNNER)

_CLEAN_EVALUATION_OVERLAY = (
    "scripts/attorney_eval_full.py",
    "scripts/harvest_skill.py",
    "src/regulatory_harvest/evaluation/attorney_admission.py",
    "src/regulatory_harvest/evaluation/attorney_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_cli.py",
    "src/regulatory_harvest/evaluation/attorney_generation.py",
    "src/regulatory_harvest/evaluation/attorney_ledger.py",
    "src/regulatory_harvest/evaluation/attorney_models.py",
    "src/regulatory_harvest/evaluation/attorney_scoring.py",
    "src/regulatory_harvest/evaluation/attorney_workflow.py",
    "src/regulatory_harvest/evaluation/attorney_v2_artifacts.py",
    "src/regulatory_harvest/evaluation/attorney_v2_compiler.py",
    "src/regulatory_harvest/evaluation/attorney_v2_models.py",
    "src/regulatory_harvest/evaluation/attorney_v2_requests.py",
    "src/regulatory_harvest/evaluation/attorney_v2_rubric.py",
    "src/regulatory_harvest/evaluation/attorney_v2_workflow.py",
    "src/regulatory_harvest/models/enums.py",
)

SOURCE_BYTES = b"Synthetic Rule. A covered operator must file notice within 10 days."
FACTS_BYTES = b"The operator is covered."


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _run(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _default_request(runner: Path, run: Path) -> dict[str, object]:
    result = _run(runner, "eval-next", "--run", str(run))
    assert result.returncode == 0, result.stderr
    request = json.loads(result.stdout)
    assert request["operation"] == "source_review"
    assert request["schema_version"] == "2.1"
    return request


def _v2_case(run: Path) -> dict[str, object]:
    return json.loads((run / "inputs" / "case.json").read_bytes())


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _assert_cli_parity(results: list[subprocess.CompletedProcess[str]]) -> None:
    assert len(results) == 2
    assert (results[0].returncode, results[0].stdout, results[0].stderr) == (
        results[1].returncode,
        results[1].stdout,
        results[1].stderr,
    )


def _extract_frozen_legacy_run(tmp_path: Path) -> Path:
    fixture = ROOT / "tests" / "fixtures" / "attorney-eval" / "legacy-ledger-repair-919eb5f.tgz.b64"
    archive = base64.b64decode(fixture.read_bytes())
    assert hashlib.sha256(archive).hexdigest() == (
        "0a13f0fbeb9c6c5841a198a811efcf1f567c91ebfbeade3f9d4214b87ee7729d"
    )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        assert all(
            not member.name.startswith("/") and ".." not in Path(member.name).parts
            for member in tar.getmembers()
        )
        tar.extractall(tmp_path, filter="data")
    return tmp_path / "completed-repair"


def _response(request: dict[str, object], report_text: str) -> dict[str, object]:
    return {
        "generation_isolation": "scripted_fixture",
        "model_name": "no-provider",
        "operation": "generate_report",
        "payload": {"report_text": report_text},
        "provider_name": "local-scripted-fixture",
        "request_fingerprint": request["request_fingerprint"],
        "response_id": None,
        "schema_version": "1.0",
        "usage": {},
    }


def _capsule(
    tmp_path: Path,
    fixture: Path,
    *,
    candidate_id: str,
    report_text: str,
    nonce: str,
    source_bytes: bytes = SOURCE_BYTES,
    facts_bytes: bytes | None = FACTS_BYTES,
    question: str = "What notice is required?",
    generation_instructions: str = (
        "Produce the attorney report from the supplied record."
    ),
    additional_source: bytes | None = None,
    complete: bool = True,
) -> Path:
    capture_root = tmp_path / f"capture-{candidate_id}"
    (capture_root / "sources").mkdir(parents=True)
    (capture_root / "generator").mkdir()
    (capture_root / "sources" / "rule.txt").write_bytes(source_bytes)
    if additional_source is not None:
        (capture_root / "sources" / "supplement.txt").write_bytes(additional_source)
    if facts_bytes is not None:
        (capture_root / "client-facts.txt").write_bytes(facts_bytes)
    (capture_root / "generator" / "descriptor.bin").write_bytes(b"test-generator")
    generation_input = {
        "candidate_id": candidate_id,
        "client_facts_path": "client-facts.txt" if facts_bytes is not None else None,
        "generation_instructions": generation_instructions,
        "generator_artifacts": [
            {"artifact_id": "generator", "path": "generator/descriptor.bin"}
        ],
        "question": question,
        "schema_version": "1.0",
        "sources": [
            {"path": "sources/rule.txt", "source_id": "source-1"},
            *(
                [{"path": "sources/supplement.txt", "source_id": "source-2"}]
                if additional_source is not None
                else []
            ),
        ],
    }
    input_path = capture_root / "generation-input.json"
    input_path.write_bytes(_canonical(generation_input))
    capsule = fixture / "capsules" / candidate_id
    attorney_generation.initialize_generation(input_path, capsule, nonce_hex=nonce)
    if not complete:
        return capsule
    request = attorney_generation.next_generation_request(capsule)
    assert request is not None
    response_path = tmp_path / f"response-{candidate_id}.json"
    response_path.write_bytes(_canonical(_response(request, report_text)))
    attorney_generation.submit_generation_response(capsule, response_path)
    return capsule


def _case(
    fixture: Path,
    candidates: list[dict[str, object]],
    *,
    schema_version: str = "1.1",
    source_bytes: bytes = SOURCE_BYTES,
    facts_bytes: bytes | None = FACTS_BYTES,
    question: str = "What notice is required?",
    additional_source: bytes | None = None,
) -> Path:
    (fixture / "sources").mkdir(parents=True, exist_ok=True)
    (fixture / "reports").mkdir(exist_ok=True)
    (fixture / "sources" / "rule.txt").write_bytes(source_bytes)
    if additional_source is not None:
        (fixture / "sources" / "supplement.txt").write_bytes(additional_source)
    if facts_bytes is not None:
        (fixture / "client-facts.txt").write_bytes(facts_bytes)
    value = {
        "as_of": "2026-08-12",
        "candidates": candidates,
        "case_id": "capsule-provenance-case",
        "client_facts_path": "client-facts.txt" if facts_bytes is not None else None,
        "jurisdiction": "Example State",
        "mode": "closed-universe",
        "question": question,
        "requested_authorities": [
            {
                "authority_id": "synthetic-rule",
                "authority_type": "regulation",
                "jurisdiction": "Example State",
                "source_ids": [
                    "source-1",
                    *( ["source-2"] if additional_source is not None else [] ),
                ],
                "title": "Synthetic Rule",
            }
        ],
        "schema_version": schema_version,
        "sources": [
            {
                "authority_type": "regulation",
                "completeness": "complete",
                "jurisdiction": "Example State",
                "language": "en",
                "path": "sources/rule.txt",
                "source_id": "source-1",
                "source_quality": "primary",
                "source_role": "official_primary",
                "title": "Synthetic Rule",
            },
            *(
                [
                    {
                        "authority_type": "regulation",
                        "completeness": "complete",
                        "jurisdiction": "Example State",
                        "language": "en",
                        "path": "sources/supplement.txt",
                        "source_id": "source-2",
                        "source_quality": "primary",
                        "source_role": "official_primary",
                        "title": "Synthetic Supplement",
                    }
                ]
                if additional_source is not None
                else []
            ),
        ],
    }
    path = fixture / "case.json"
    path.write_bytes(_canonical(value))
    return path


def _capsule_candidate(candidate_id: str, role: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "external_report_path": None,
        "generation_capsule_path": f"capsules/{candidate_id}",
        "role": role,
    }


def _external_candidate(candidate_id: str, role: str, path: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "external_report_path": path,
        "generation_capsule_path": None,
        "role": role,
    }


def _claimed_capsule_provenance(
    candidate_id: str,
    report_text: str,
) -> dict[str, object]:
    return {
        "capsule_root": hashlib.sha256(f"claimed:{candidate_id}".encode()).hexdigest(),
        "generation_record": {
            "candidate_id": candidate_id,
            "capture_fingerprint": hashlib.sha256(
                f"capture:{candidate_id}".encode()
            ).hexdigest(),
            "client_facts_hash": hashlib.sha256(FACTS_BYTES).hexdigest(),
            "generation_isolation": "scripted_fixture",
            "generator_artifact_hashes": {
                "generator": hashlib.sha256(b"claimed-generator").hexdigest()
            },
            "model_name": "claimed-model",
            "nonce_fingerprint": hashlib.sha256(
                f"nonce:{candidate_id}".encode()
            ).hexdigest(),
            "provider_name": "claimed-provider",
            "report_hash": hashlib.sha256(report_text.encode()).hexdigest(),
            "request_fingerprint": hashlib.sha256(
                f"request:{candidate_id}".encode()
            ).hexdigest(),
            "response_fingerprint": hashlib.sha256(
                f"response:{candidate_id}".encode()
            ).hexdigest(),
            "response_id": None,
            "schema_version": "1.0",
            "source_hashes": {"source-1": hashlib.sha256(SOURCE_BYTES).hexdigest()},
            "usage": {},
        },
        "generation_question": "What notice is required?",
        "kind": "capsule",
    }


def _claimed_two_report_case() -> AttorneyEvaluationCase:
    source_hash = hashlib.sha256(SOURCE_BYTES).hexdigest()
    reports = ("Claimed report A.", "Claimed report B.")
    return AttorneyEvaluationCase(
        schema_version="1.1",
        case_id="claimed-provenance-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What notice is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 12),
        requested_authorities=[
            RequestedAuthority(
                authority_id="synthetic-rule",
                title="Synthetic Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["source-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="source-1",
                title="Synthetic Rule",
                normalized_text=SOURCE_BYTES.decode(),
                content_hash=source_hash,
                jurisdiction="Example State",
                authority_type="regulation",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id=candidate_id,
                role=(
                    CandidateRole.CANDIDATE
                    if index == 0
                    else CandidateRole.COMPARATOR
                ),
                report_text=report_text,
                report_hash=hashlib.sha256(report_text.encode()).hexdigest(),
                validation_receipt=_claimed_capsule_provenance(
                    candidate_id, report_text
                ),
            )
            for index, (candidate_id, report_text) in enumerate(
                (("candidate-a", reports[0]), ("candidate-b", reports[1]))
            )
        ],
        client_facts=FACTS_BYTES.decode(),
    )


def test_programmatic_fake_capsule_claims_cannot_authorize_formal_comparison(
    tmp_path: Path,
) -> None:
    case = _claimed_two_report_case()
    full_run = tmp_path / "full"
    with pytest.raises(EvaluationSourceParityUnprovenError):
        initialize_evaluation(case, full_run, seed_hex="0" * 64)
    assert not full_run.exists()

    portable_path = ROOT / "scripts" / "attorney_eval_portable.py"
    spec = importlib.util.spec_from_file_location(
        "claimed_attorney_eval_portable", portable_path
    )
    assert spec is not None and spec.loader is not None
    portable = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = portable
    spec.loader.exec_module(portable)
    portable_run = tmp_path / "portable"
    with pytest.raises(portable.EvaluationSourceParityUnprovenError):
        portable.initialize_evaluation(
            case.model_dump(mode="json"), portable_run, seed_hex="0" * 64
        )
    assert not portable_run.exists()


def test_eval_init_loads_verified_capsule_report_and_provenance_with_runner_parity(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    report = "# Exact report\r\n\r\nNotice is due within 10 days.\r\n"
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text=report,
        nonce="1" * 64,
    )
    case_path = _case(fixture, [_capsule_candidate("candidate-a", "candidate")])
    runs = [tmp_path / "full", tmp_path / "portable"]

    for runner, run in zip(RUNNERS, runs, strict=True):
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "a" * 64,
        )
        assert result.returncode == 0, result.stderr

    assert _tree_bytes(runs[0]) == _tree_bytes(runs[1])
    envelope = _v2_case(runs[0])
    candidate = envelope["case"]["candidates"][0]
    assert envelope["case"]["schema_version"] == "1.1"
    assert candidate["report_text"] == report
    assert candidate["validation_receipt"]["kind"] == "capsule"
    assert candidate["validation_receipt"]["capsule_root"] == json.loads(
        (fixture / "capsules" / "candidate-a" / "generation-manifest.json").read_bytes()
    )["manifest_fingerprint"]
    assert candidate["validation_receipt"]["generation_record"]["candidate_id"] == "candidate-a"
    assert "generation_capsule_path" not in json.dumps(envelope)
    assert _default_request(FULL_RUNNER, runs[0]) == _default_request(
        PORTABLE_RUNNER, runs[1]
    )


def test_full_eval_init_preserves_capsule_provenance_under_protocol_21(tmp_path: Path) -> None:
    """The 2.1 default freezes the same verified capsule content without path leakage."""
    fixture = tmp_path / "fixture"
    report = "# Exact report\n\nNotice is due within 10 days.\n"
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text=report,
        nonce="2" * 64,
    )
    case_path = _case(fixture, [_capsule_candidate("candidate-a", "candidate")])
    run = tmp_path / "full"

    result = _run(
        FULL_RUNNER,
        "eval-init",
        "--case",
        str(case_path),
        "--run",
        str(run),
        "--seed-hex",
        "b" * 64,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads((run / "run-manifest.json").read_bytes())["protocol_version"] == "2.1"
    envelope = json.loads((run / "inputs" / "case.json").read_bytes())
    candidate = envelope["case"]["candidates"][0]
    receipt = candidate["validation_receipt"]
    assert candidate["report_text"] == report
    assert receipt["kind"] == "capsule"
    assert receipt["capsule_root"] == json.loads(
        (fixture / "capsules" / "candidate-a" / "generation-manifest.json").read_bytes()
    )["manifest_fingerprint"]
    assert receipt["generation_record"]["candidate_id"] == "candidate-a"
    assert "generation_capsule_path" not in json.dumps(envelope)


def test_full_eval_init_runs_from_clean_tracked_snapshot_without_portable_fallback(
    tmp_path: Path,
) -> None:
    archived = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        timeout=10,
    )
    if archived.returncode != 0:
        pytest.skip("clean tracked snapshot requires a Git checkout")
    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
        assert all(
            not member.name.startswith("/") and ".." not in Path(member.name).parts
            for member in archive.getmembers()
        )
        archive.extractall(clean_root)
    for relative in _CLEAN_EVALUATION_OVERLAY:
        source = ROOT / relative
        target = clean_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    # If the dependency probe accidentally chooses the portable runner, this
    # invocation must fail; success therefore proves full-runtime routing.
    (clean_root / "scripts" / "harvest_portable.py").unlink()

    fixture = tmp_path / "fixture"
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="Clean snapshot report.",
        nonce="f" * 64,
    )
    case_path = _case(fixture, [_capsule_candidate("candidate-a", "candidate")])
    direct_run = tmp_path / "direct-clean-run"
    direct = subprocess.run(
        [
            sys.executable,
            str(clean_root / "scripts" / "attorney_eval_full.py"),
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(direct_run),
            "--seed-hex",
            "e" * 64,
        ],
        cwd=clean_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    run = tmp_path / "clean-run"
    result = subprocess.run(
        [
            sys.executable,
            str(clean_root / "scripts" / "harvest_skill.py"),
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "e" * 64,
        ],
        cwd=clean_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert direct.returncode == 0, direct.stderr
    assert result.returncode == 0, result.stderr
    assert _tree_bytes(direct_run) == _tree_bytes(run)
    assert (
        json.loads((run / "run-manifest.json").read_bytes())["calls"][0]["operation"]
        == "source_review"
    )


@pytest.mark.parametrize("runner", RUNNERS)
def test_eval_init_rejects_legacy_self_attested_filesystem_case(
    runner: Path,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    (fixture / "receipts").mkdir(parents=True)
    (fixture / "reports").mkdir()
    (fixture / "reports" / "report.md").write_bytes(b"A post-hoc report.")
    (fixture / "receipts" / "access.json").write_bytes(
        _canonical(
            {
                "client_facts_hash": hashlib.sha256(FACTS_BYTES).hexdigest(),
                "schema_version": "1.0",
                "source_hashes": {"source-1": hashlib.sha256(SOURCE_BYTES).hexdigest()},
            }
        )
    )
    case_path = _case(
        fixture,
        [
            {
                "access_receipt_path": "receipts/access.json",
                "candidate_id": "candidate-a",
                "path": "reports/report.md",
                "role": "candidate",
            }
        ],
        schema_version="1.0",
    )
    run = tmp_path / "run"

    result = _run(
        runner,
        "eval-init",
        "--case",
        str(case_path),
        "--run",
        str(run),
        "--seed-hex",
        "b" * 64,
    )

    assert result.returncode == 2
    assert not run.exists()


@pytest.mark.parametrize("pair", ["external", "mixed"])
def test_eval_init_rejects_unproven_two_report_comparison_before_source_review(
    pair: str,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    (fixture / "reports").mkdir(parents=True)
    (fixture / "reports" / "a.md").write_bytes(b"External report A.")
    (fixture / "reports" / "b.md").write_bytes(b"External report B.")
    first = _external_candidate("candidate-a", "candidate", "reports/a.md")
    if pair == "external":
        second = _external_candidate("candidate-b", "comparator", "reports/b.md")
    else:
        _capsule(
            tmp_path,
            fixture,
            candidate_id="candidate-b",
            report_text="Capsule report B.",
            nonce="2" * 64,
        )
        second = _capsule_candidate("candidate-b", "comparator")
    case_path = _case(fixture, [first, second])
    results = []
    for runner in RUNNERS:
        run = tmp_path / f"{pair}-{runner.stem}"
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "c" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
        assert not run.exists()
    _assert_cli_parity(results)


def test_eval_init_accepts_two_verified_capsules_with_byte_identical_runners(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    for candidate_id, report, nonce in (
        ("candidate-a", "Capsule report A.", "3" * 64),
        ("candidate-b", "Capsule report B.", "4" * 64),
    ):
        _capsule(
            tmp_path,
            fixture,
            candidate_id=candidate_id,
            report_text=report,
            nonce=nonce,
        )
    case_path = _case(
        fixture,
        [
            _capsule_candidate("candidate-a", "candidate"),
            _capsule_candidate("candidate-b", "comparator"),
        ],
    )
    runs = [tmp_path / "full", tmp_path / "portable"]

    for runner, run in zip(RUNNERS, runs, strict=True):
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "d" * 64,
        )
        assert result.returncode == 0, result.stderr

    assert _tree_bytes(runs[0]) == _tree_bytes(runs[1])
    candidates = _v2_case(runs[0])["case"]["candidates"]
    assert {item["validation_receipt"]["kind"] for item in candidates} == {"capsule"}
    assert _default_request(FULL_RUNNER, runs[0]) == _default_request(
        PORTABLE_RUNNER, runs[1]
    )


def test_protocol_22_init_preserves_capsule_provenance_without_public_paths(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    capsule = _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="A covered operator must file notice within 10 days.",
        nonce="8" * 64,
    )
    case_path = _case(
        fixture,
        [_capsule_candidate("candidate-a", "candidate")],
    )
    run = tmp_path / "v22-run"

    initialized = _run(
        FULL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(case_path),
        "--run",
        str(run),
        "--seed-hex",
        "9" * 64,
    )

    assert initialized.returncode == 0, initialized.stderr
    frozen = json.loads((run / "inputs" / "case.json").read_bytes())
    candidate = frozen["case"]["candidates"][0]
    assert candidate["validation_receipt"]["kind"] == "capsule"
    assert candidate["validation_receipt"]["capsule_root"] == json.loads(
        (capsule / "generation-manifest.json").read_bytes()
    )["manifest_fingerprint"]
    status = _run(FULL_RUNNER, "eval-status", "--run", str(run))
    verified = _run(FULL_RUNNER, "eval-verify", "--run", str(run))
    assert status.returncode == verified.returncode == 0
    public_bytes = initialized.stdout + status.stdout + verified.stdout
    assert str(tmp_path) not in public_bytes
    assert str(capsule) not in public_bytes


def test_eval_init_rejects_different_generation_instructions_before_source_review(
    tmp_path: Path,
) -> None:
    """A formal comparison must bind both reports to the same generation task."""
    fixture = tmp_path / "fixture"
    for candidate_id, report, nonce, instructions in (
        (
            "candidate-a",
            "Capsule report A.",
            "3" * 64,
            "Produce the attorney report from the supplied record.",
        ),
        (
            "candidate-b",
            "Capsule report B.",
            "4" * 64,
            "Produce only a short executive summary from the supplied record.",
        ),
    ):
        _capsule(
            tmp_path,
            fixture,
            candidate_id=candidate_id,
            report_text=report,
            nonce=nonce,
            generation_instructions=instructions,
        )
    case_path = _case(
        fixture,
        [
            _capsule_candidate("candidate-a", "candidate"),
            _capsule_candidate("candidate-b", "comparator"),
        ],
    )
    results = []
    for runner in RUNNERS:
        run = tmp_path / runner.stem
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "d" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
        assert not run.exists()
    _assert_cli_parity(results)



@pytest.mark.parametrize(
    "mutation",
    [
        "case-source-changed",
        "case-source-added",
        "capsule-source-added",
        "client-facts-changed",
        "case-facts-removed",
        "capsule-facts-removed",
        "question-changed",
    ],
)
def test_eval_init_rejects_common_evidence_mismatch_before_source_review(
    mutation: str,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    capsule_extra = b"Synthetic supplement text." if mutation == "capsule-source-added" else None
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="Capsule report.",
        nonce="5" * 64,
        facts_bytes=(None if mutation == "capsule-facts-removed" else FACTS_BYTES),
        additional_source=capsule_extra,
    )
    case_path = _case(
        fixture,
        [_capsule_candidate("candidate-a", "candidate")],
        source_bytes=(
            b"Changed common rule text."
            if mutation == "case-source-changed"
            else SOURCE_BYTES
        ),
        facts_bytes=(
            None
            if mutation == "case-facts-removed"
            else (
                b"Changed common facts."
                if mutation == "client-facts-changed"
                else FACTS_BYTES
            )
        ),
        question=(
            "A different question?"
            if mutation == "question-changed"
            else "What notice is required?"
        ),
        additional_source=(
            b"Synthetic supplement text." if mutation == "case-source-added" else None
        ),
    )
    results = []
    for runner in RUNNERS:
        run = tmp_path / runner.stem
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "e" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
        assert not run.exists()
    _assert_cli_parity(results)


@pytest.mark.parametrize("mutation", ["candidate-id", "incomplete"])
def test_eval_init_rejects_malformed_or_incomplete_capsule_as_input(
    mutation: str,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="Capsule report.",
        nonce="6" * 64,
        complete=mutation != "incomplete",
    )
    candidate = _capsule_candidate("candidate-a", "candidate")
    if mutation == "candidate-id":
        candidate["candidate_id"] = "candidate-other"
    case_path = _case(fixture, [candidate])

    results = []
    for runner in RUNNERS:
        run = tmp_path / f"{runner.stem}-run"
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "f" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert not run.exists()
    _assert_cli_parity(results)


def test_eval_init_rejects_tampered_candidate_capsule_before_source_review(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    capsule = _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="Capsule report.",
        nonce="7" * 64,
    )
    (capsule / "report.md").write_bytes(b"Tampered report.")
    case_path = _case(fixture, [_capsule_candidate("candidate-a", "candidate")])

    results = []
    for runner in RUNNERS:
        run = tmp_path / f"{runner.stem}-run"
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "8" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert json.loads(result.stderr)["code"] == "EVALUATION_INPUT_INVALID"
        assert not run.exists()
    _assert_cli_parity(results)


@pytest.mark.parametrize(
    "mutation",
    [
        "schema-missing",
        "schema-1.0-new-shape",
        "old-receipt-key",
        "both-report-sources",
        "neither-report-source",
        "capsule-path-bool",
        "external-path-int",
    ],
)
def test_eval_init_rejects_mixed_schema_xor_and_strict_type_violations(
    mutation: str,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    _capsule(
        tmp_path,
        fixture,
        candidate_id="candidate-a",
        report_text="Capsule report.",
        nonce="9" * 64,
    )
    (fixture / "reports").mkdir(parents=True)
    (fixture / "reports" / "external.md").write_bytes(b"External report.")
    case_path = _case(fixture, [_capsule_candidate("candidate-a", "candidate")])
    case = json.loads(case_path.read_bytes())
    candidate = case["candidates"][0]
    if mutation == "schema-missing":
        case.pop("schema_version")
    elif mutation == "schema-1.0-new-shape":
        case["schema_version"] = "1.0"
    elif mutation == "old-receipt-key":
        candidate["access_receipt_path"] = "receipt.json"
    elif mutation == "both-report-sources":
        candidate["external_report_path"] = "reports/external.md"
    elif mutation == "neither-report-source":
        candidate["generation_capsule_path"] = None
    elif mutation == "capsule-path-bool":
        candidate["generation_capsule_path"] = True
    else:
        candidate["generation_capsule_path"] = None
        candidate["external_report_path"] = 1
    case_path.write_bytes(_canonical(case))

    results = []
    for runner in RUNNERS:
        run = tmp_path / f"{runner.stem}-run"
        result = _run(
            runner,
            "eval-init",
            "--case",
            str(case_path),
            "--run",
            str(run),
            "--seed-hex",
            "a" * 64,
        )
        results.append(result)
        assert result.returncode == 2
        assert not run.exists()
    _assert_cli_parity(results)


def test_frozen_protocol_13_fixture_replays_read_only_with_both_runners(
    tmp_path: Path,
) -> None:
    """Provenance-era runs remain verifiable only as immutable retained fixtures."""
    run = _extract_frozen_legacy_run(tmp_path)
    before = _tree_bytes(run)
    results = [_run(runner, "eval-status", "--run", str(run)) for runner in RUNNERS]
    verifies = [_run(runner, "eval-verify", "--run", str(run)) for runner in RUNNERS]

    assert [result.returncode for result in results] == [0, 0]
    assert [result.returncode for result in verifies] == [0, 0]
    assert results[0].stdout == results[1].stdout
    assert verifies[0].stdout == verifies[1].stdout
    assert _tree_bytes(run) == before


def _submit_dynamic_response(
    runner: Path,
    run: Path,
    response_path: Path,
    scripted_payload: dict[str, object],
) -> subprocess.CompletedProcess[str]:
    next_result = _run(runner, "eval-next", "--run", str(run))
    assert next_result.returncode == 0, next_result.stderr
    request = json.loads(next_result.stdout)
    payload = copy.deepcopy(scripted_payload)
    operation = request["operation"]
    if operation == "admit_case":
        payload["request_fingerprint"] = request["request_fingerprint"]
    elif operation == "build_ledger":
        payload["case_fingerprint"] = request["safe_metadata"][
            "source_record_fingerprint"
        ]
    elif operation == "audit_ledger":
        payload["request_fingerprint"] = request["request_fingerprint"]
    else:
        assert operation == "grade_report"
        payload["request_fingerprint"] = request["request_fingerprint"]
        payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
        payload["ledger_fingerprint"] = request["safe_metadata"][
            "legal_ledger_fingerprint"
        ]
    response = {
        "judge_isolation": "scripted_fixture",
        "model_name": "no-provider",
        "operation": operation,
        "payload": payload,
        "provider_name": "local-scripted-fixture",
        "request_fingerprint": request["request_fingerprint"],
        "response_id": None,
        "schema_version": "1.0",
        "usage": {},
    }
    response_path.write_bytes(_canonical(response))
    return _run(
        runner,
        "eval-submit",
        "--run",
        str(run),
        "--response",
        str(response_path),
    )


def test_one_external_report_initializes_source_review_without_comparison(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    shutil.copytree(ROOT / "tests" / "fixtures" / "attorney-eval", fixture)
    runs = [tmp_path / "full", tmp_path / "portable"]

    for runner, run in zip(RUNNERS, runs, strict=True):
        initialized = _run(
            runner,
            "eval-init",
            "--case",
            str(fixture / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "b" * 64,
        )
        assert initialized.returncode == 0, initialized.stderr
        assert _default_request(runner, run)["operation"] == "source_review"

    assert _tree_bytes(runs[0]) == _tree_bytes(runs[1])
    manifest = json.loads((runs[0] / "run-manifest.json").read_bytes())
    assert manifest["protocol_version"] == "2.1"
    assert manifest["phase"] == "source_review"
    assert manifest["terminal_status"] is None


def test_legacy_schema_10_retained_run_still_verifies_without_migration(
    tmp_path: Path,
) -> None:
    source_hash = hashlib.sha256(SOURCE_BYTES).hexdigest()
    report_text = "Legacy retained report."
    report_hash = hashlib.sha256(report_text.encode()).hexdigest()
    case = AttorneyEvaluationCase(
        schema_version="1.0",
        case_id="legacy-retained-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What notice is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 12),
        requested_authorities=[
            RequestedAuthority(
                authority_id="synthetic-rule",
                title="Synthetic Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["source-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="source-1",
                title="Synthetic Rule",
                normalized_text=SOURCE_BYTES.decode(),
                content_hash=source_hash,
                jurisdiction="Example State",
                authority_type="regulation",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="legacy-candidate",
                role=CandidateRole.CANDIDATE,
                report_text=report_text,
                report_hash=report_hash,
                validation_receipt={
                    "client_facts_hash": hashlib.sha256(b"").hexdigest(),
                    "schema_version": "1.0",
                    "source_hashes": {"source-1": source_hash},
                },
            )
        ],
    )
    envelope = CaseEnvelope(
        case=case,
        case_fingerprint=hashlib.sha256(
            canonical_json_bytes(case.model_dump(mode="json"))
        ).hexdigest(),
        seed_fingerprint="1" * 64,
        assignments=[
            BlindAssignment(anonymous_label="A", candidate_id="legacy-candidate")
        ],
    )
    data = canonical_json_bytes(envelope.model_dump(mode="json"))

    loaded = _load_model_bytes(data, CaseEnvelope, location="legacy case envelope")

    assert loaded.case.schema_version == "1.0"
    assert canonical_json_bytes(loaded.model_dump(mode="json")) == data

    portable_path = ROOT / "scripts" / "attorney_eval_portable.py"
    spec = importlib.util.spec_from_file_location(
        "legacy_attorney_eval_portable", portable_path
    )
    assert spec is not None and spec.loader is not None
    portable = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = portable
    spec.loader.exec_module(portable)
    envelope_payload = portable.freeze_case(case.model_dump(mode="json"), seed_hex="c" * 64)
    request = portable.build_admission_packet(envelope_payload)
    call = portable._pending_call("admission", request)
    files = {
        portable._CASE_ENVELOPE_PATH: portable.canonical_json_bytes(envelope_payload),
        portable._RUBRIC_PATH: portable.canonical_json_bytes(portable.RUBRIC_V1),
        call["request_artifact_path"]: portable.canonical_json_bytes(request),
    }
    manifest = portable._manifest(
        case_fingerprint=envelope_payload["case_fingerprint"],
        case_envelope_hash=portable._sha256(files[portable._CASE_ENVELOPE_PATH]),
        rubric_fingerprint=portable._model_fingerprint(portable.RUBRIC_V1),
        legal_ledger_hash=None,
        result_hash=None,
        judge_calls=[call],
        artifacts=[
            portable._artifact_record(path, artifact) for path, artifact in files.items()
        ],
        state="admission",
        retry_count=0,
        terminal_status=None,
    )
    run = tmp_path / "legacy-run"
    with portable._open_run_storage(run, initialize=True) as storage:
        for path, artifact in sorted(files.items()):
            storage.atomic_write(path, artifact, mutable=False)
        portable._write_manifest(storage, manifest)
        storage.assert_root_identity()

    retained_before = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }

    results = [_run(runner, "eval-verify", "--run", str(run)) for runner in RUNNERS]
    assert [result.returncode for result in results] == [0, 0]
    assert [json.loads(result.stdout)["ok"] for result in results] == [True, True]
    assert results[0].stdout == results[1].stdout
    assert {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    } == retained_before
