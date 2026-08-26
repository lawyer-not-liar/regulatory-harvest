"""Public full-runtime CLI coverage for ``delivery-readiness-v1``."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import io
import json
import os
import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    load_verified_readiness_context_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    AbsoluteDispositionV2,
    DeliveryReadinessTierV1,
    HistoricalV22CrossCheckStatusV1,
    HistoricalV22CrossCheckV1,
    ReadinessEvaluatorRequestV1,
    ReadinessPhaseV1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    continue_readiness_v1,
    next_readiness_request_v1,
)
from regulatory_harvest.storage import canonical_json_bytes

ROOT = Path(__file__).parents[2]
FULL_RUNNER = ROOT / "scripts" / "attorney_eval_full.py"
PUBLIC_RUNNER = ROOT / "scripts" / "harvest_skill.py"
EVALUATION_TESTS = ROOT / "tests" / "evaluation"


@lru_cache(maxsize=1)
def _runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("readiness_cli_full_runner", FULL_RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _support_modules(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, ModuleType]:
    monkeypatch.syspath_prepend(str(EVALUATION_TESTS))
    return (
        importlib.import_module("test_attorney_readiness_inputs"),
        importlib.import_module("test_attorney_readiness_workflow"),
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _initialize_arguments(source: object, run: Path) -> list[str]:
    return [
        "eval-readiness-init",
        "--baseline-run",
        str(source.baseline_run_dir),
        "--qualification-run",
        str(source.qualification_run_dir),
        "--generation-run",
        str(source.generation_run_dir),
        "--validation-receipt",
        str(source.validation_receipt_path),
        "--run",
        str(run),
    ]


def test_readiness_parser_locks_the_five_opt_in_command_surfaces() -> None:
    parser = _runner()._parser()
    init = parser.parse_args(
        [
            "eval-readiness-init",
            "--baseline-run",
            "baseline",
            "--qualification-run",
            "qualification",
            "--generation-run",
            "generation",
            "--validation-receipt",
            "receipt.json",
            "--run",
            "readiness",
            "--historical-v22-run",
            "history",
            "--historical-report-label",
            "B",
        ]
    )
    assert vars(init) == {
        "baseline_run": "baseline",
        "command": "eval-readiness-init",
        "generation_run": "generation",
        "historical_report_label": "B",
        "historical_v22_run": "history",
        "qualification_run": "qualification",
        "run": "readiness",
        "validation_receipt": "receipt.json",
    }

    for command in (
        "eval-readiness-next",
        "eval-readiness-status",
        "eval-readiness-verify",
    ):
        assert vars(parser.parse_args([command, "--run", "readiness"])) == {
            "command": command,
            "run": "readiness",
        }

    submit = parser.parse_args(
        [
            "eval-readiness-submit-safe",
            "--run",
            "readiness",
            "--response",
            "response.json",
            "--provider-name",
            "provider",
            "--model-name",
            "model",
            "--judge-isolation",
            "fresh_context",
        ]
    )
    assert vars(submit) == {
        "command": "eval-readiness-submit-safe",
        "judge_isolation": "fresh_context",
        "model_name": "model",
        "provider_name": "provider",
        "response": "response.json",
        "run": "readiness",
    }
    assert "eval-readiness-stop" not in parser.format_help()


@pytest.mark.parametrize(
    ("command", "expected_flags"),
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
            ),
        ),
        ("eval-readiness-next", ("--run",)),
        (
            "eval-readiness-submit-safe",
            ("--run", "--response", "--provider-name", "--model-name", "--judge-isolation"),
        ),
        ("eval-readiness-status", ("--run",)),
        ("eval-readiness-verify", ("--run",)),
    ],
)
def test_public_runner_exposes_exact_readiness_help(
    command: str,
    expected_flags: tuple[str, ...],
) -> None:
    import subprocess

    result = subprocess.run(
        [sys.executable, str(PUBLIC_RUNNER), command, "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode, result.stderr) == (0, "")
    assert f"harvest-skill {command}" in result.stdout
    for flag in expected_flags:
        assert flag in result.stdout


def test_readiness_init_refuses_unpaired_history_before_creating_a_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run = tmp_path / "readiness-run"
    status = _runner().main(
        [
            "eval-readiness-init",
            "--baseline-run",
            "missing-baseline",
            "--qualification-run",
            "missing-qualification",
            "--generation-run",
            "missing-generation",
            "--validation-receipt",
            "missing-receipt",
            "--run",
            str(run),
            "--historical-v22-run",
            "history-only",
        ]
    )

    captured = capsys.readouterr()
    assert status == 2
    assert json.loads(captured.err) == {
        "code": "READINESS_INPUT_INVALID",
        "message": "Historical Protocol 2.2 options must be supplied together.",
    }
    assert captured.out == ""
    assert not run.exists()


def test_readiness_init_and_next_return_only_bounded_public_state_and_exact_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs, _ = _support_modules(monkeypatch)
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "readiness-run"

    status = _runner().main(_initialize_arguments(source, run))
    initialized = json.loads(capsys.readouterr().out)

    assert status == 0
    assert set(initialized) == {
        "baseline_locked_strict_equivalent_disposition",
        "delivery_readiness",
        "engine_paused",
        "manifest_fingerprint",
        "pending_operation",
        "protocol_version",
    }
    assert initialized["protocol_version"] == "delivery-readiness-v1"
    assert initialized["baseline_locked_strict_equivalent_disposition"] is None
    assert initialized["delivery_readiness"] is None
    assert initialized["engine_paused"] is False
    assert initialized["pending_operation"] == {
        "fragment_class": "ordinary_batch",
        "lane": 1,
        "operation": "baseline_locked_grade",
    }
    pending_context = load_verified_readiness_context_v1(run)
    assert _runner()._readiness_context_exit_code(pending_context) == 0
    assert _runner()._readiness_context_exit_code(
        pending_context, engine_paused=True
    ) == 6
    public_bytes = canonical_json_bytes(initialized)
    assert str(tmp_path).encode() not in public_bytes
    assert source.report_text.encode() not in public_bytes

    next_status = _runner().main(["eval-readiness-next", "--run", str(run)])
    request = json.loads(capsys.readouterr().out)
    expected = next_readiness_request_v1(run)
    assert expected is not None
    assert next_status == 0
    assert request == expected.model_dump(mode="json")


def test_submit_safe_compiles_inner_payload_and_rejects_mechanical_invalidity_write_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs, workflow_tests = _support_modules(monkeypatch)
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "readiness-run"
    assert _runner().main(_initialize_arguments(source, run)) == 0
    capsys.readouterr()

    request = cast(ReadinessEvaluatorRequestV1, next_readiness_request_v1(run))
    response_path = tmp_path / "inner-response.json"
    response_path.write_bytes(
        canonical_json_bytes(workflow_tests._draft(request, grade_mode="met"))
    )
    flags = [
        "--provider-name",
        "public-test-provider",
        "--model-name",
        "public-test-model",
        "--judge-isolation",
        "fresh_context",
    ]
    before_partial = _tree_bytes(run)
    partial_status = _runner().main(
        [
            "eval-readiness-submit-safe",
            "--run",
            str(run),
            "--response",
            str(response_path),
            "--provider-name",
            "provider-only",
        ]
    )
    partial = json.loads(capsys.readouterr().out)
    assert partial_status == 2
    assert partial["accepted"] is False
    assert partial["preflight"]["diagnostics"] == [
        "READINESS_EXTERNAL_RESPONSE_INVALID"
    ]
    assert _tree_bytes(run) == before_partial

    accepted_status = _runner().main(
        [
            "eval-readiness-submit-safe",
            "--run",
            str(run),
            "--response",
            str(response_path),
            *flags,
        ]
    )
    accepted = json.loads(capsys.readouterr().out)
    assert accepted_status == 0
    assert accepted["accepted"] is True
    assert accepted["preflight"] == {"diagnostics": [], "valid": True}
    assert accepted["status"]["pending_operation"] is not None

    before = _tree_bytes(run)
    invalid_bytes = (
        canonical_json_bytes({}),
        b'{ "noncanonical": true }',
        b"x" * (1024 * 1024 + 1),
    )
    for response_bytes in invalid_bytes:
        response_path.write_bytes(response_bytes)
        refused_status = _runner().main(
            [
                "eval-readiness-submit-safe",
                "--run",
                str(run),
                "--response",
                str(response_path),
                *flags,
            ]
        )
        refused = json.loads(capsys.readouterr().out)
        assert refused_status == 2
        assert refused == {
            "accepted": False,
            "preflight": {
                "diagnostics": ["READINESS_EXTERNAL_RESPONSE_INVALID"],
                "valid": False,
            },
        }
        assert _tree_bytes(run) == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-kind controls")
def test_readiness_response_control_rejects_aliases_and_nonregular_files(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(canonical_json_bytes({}))
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)
    fifo = tmp_path / "response.fifo"
    os.mkfifo(fifo)

    for path in (symlink, hardlink, fifo):
        assert _runner()._read_guarded_readiness_object(path) is None


def test_terminal_status_verify_and_human_projection_keep_dispositions_distinct(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, workflow_tests = _support_modules(monkeypatch)
    run, _ = workflow_tests._initialize_real(tmp_path, limitations=None)
    outcome = asyncio.run(
        continue_readiness_v1(run, workflow_tests.ScriptedEvaluator(grade_mode="met"))
    )
    assert outcome.result is not None

    status_code = _runner().main(["eval-readiness-status", "--run", str(run)])
    status = json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert status == {
        "baseline_locked_strict_equivalent_disposition": "PASS",
        "delivery_readiness": "HIGH_ASSURANCE",
        "engine_paused": False,
        "manifest_fingerprint": load_verified_readiness_context_v1(
            run
        ).manifest.manifest_fingerprint,
        "pending_operation": None,
        "protocol_version": "delivery-readiness-v1",
    }

    verification_code = _runner().main(["eval-readiness-verify", "--run", str(run)])
    verification = json.loads(capsys.readouterr().out)
    context = load_verified_readiness_context_v1(run)
    assert verification_code == 0
    assert verification == {
        "baseline_locked_strict_equivalent_disposition": "PASS",
        "delivery_readiness": "HIGH_ASSURANCE",
        "issue_codes": [],
        "manifest_fingerprint": context.manifest.manifest_fingerprint,
        "ok": True,
        "protocol_version": "delivery-readiness-v1",
        "result_fingerprint": outcome.result.result_fingerprint,
        "root_hash": context.manifest.root_hash,
        "strict_equivalent_scoring_contract_fingerprint": (
            context.manifest.strict_equivalent_scoring_contract_fingerprint
        ),
    }

    historical_result = outcome.result.model_copy(
        update={
            "delivery_readiness": DeliveryReadinessTierV1.REVIEW_READY_WITH_GAPS,
            "historical_v22_strict_disposition": AbsoluteDispositionV2.FAIL,
            "historical_v22_cross_check_status": (
                HistoricalV22CrossCheckStatusV1.DISPOSITION_DIFFERS
            ),
        }
    )
    historical_context = replace(context, result=historical_result)
    historical_status = _runner()._readiness_status_payload(historical_context)
    assert historical_status == {
        "baseline_locked_strict_equivalent_disposition": "PASS",
        "delivery_readiness": "REVIEW_READY_WITH_GAPS",
        "engine_paused": False,
        "historical_v22_cross_check_status": "DISPOSITION_DIFFERS",
        "historical_v22_strict_disposition": "FAIL",
        "manifest_fingerprint": context.manifest.manifest_fingerprint,
        "pending_operation": None,
        "protocol_version": "delivery-readiness-v1",
    }
    assert _runner().render_readiness_status_human_v1(historical_status).splitlines() == [
        "Baseline-locked strict-equivalent: PASS",
        "Historical Protocol 2.2 strict disposition: FAIL (cross-check differs)",
        "Delivery readiness: REVIEW_READY_WITH_GAPS",
    ]
    assert _runner().render_readiness_status_human_v1(status).splitlines() == [
        "Baseline-locked strict-equivalent: PASS",
        "Historical Protocol 2.2 strict disposition: not supplied",
        "Delivery readiness: HIGH_ASSURANCE",
    ]
    assert _runner()._readiness_context_exit_code(historical_context) == 0

    matching_result = historical_result.model_copy(
        update={
            "historical_v22_strict_disposition": AbsoluteDispositionV2.PASS,
            "historical_v22_cross_check_status": HistoricalV22CrossCheckStatusV1.MATCH,
        }
    )
    matching_status = _runner()._readiness_status_payload(
        replace(context, result=matching_result)
    )
    assert matching_status["historical_v22_cross_check_status"] == "MATCH"
    assert "(cross-check matches)" in _runner().render_readiness_status_human_v1(
        matching_status
    )

    pending_history = HistoricalV22CrossCheckV1(
        report_hash=context.manifest.report_hash,
        strict_disposition="FAIL",
        result_fingerprint="1" * 64,
        manifest_fingerprint="2" * 64,
        baseline_fingerprint="3" * 64,
        grader_aggregate_fingerprints=("4" * 64, "5" * 64),
        reason_codes=("SYNTHETIC",),
        baseline_comparable=True,
        report_comparable=True,
    )
    pending_inputs = replace(context.inputs, historical_v22=pending_history)
    pending_history_status = _runner()._readiness_status_payload(
        replace(context, inputs=pending_inputs, result=None)
    )
    assert pending_history_status["historical_v22_cross_check_status"] is None
    assert "(cross-check pending)" in _runner().render_readiness_status_human_v1(
        pending_history_status
    )
    for mutation, expected in (
        ({"baseline_comparable": False}, "BASELINE_NOT_COMPARABLE"),
        ({"report_comparable": False}, "REPORT_NOT_COMPARABLE"),
    ):
        mutated_history = pending_history.model_copy(update=mutation)
        mutated_status = _runner()._readiness_status_payload(
            replace(
                context,
                inputs=replace(context.inputs, historical_v22=mutated_history),
                result=None,
            )
        )
        assert mutated_status["historical_v22_cross_check_status"] == expected

    nondeliverable = historical_result.model_copy(
        update={"delivery_readiness": DeliveryReadinessTierV1.NOT_DELIVERABLE}
    )
    assert _runner()._readiness_context_exit_code(
        replace(context, result=nondeliverable)
    ) == 4
    inconclusive_manifest = context.manifest.model_copy(
        update={
            "phase": ReadinessPhaseV1.INCONCLUSIVE,
            "terminal_status": "INCONCLUSIVE",
            "pending_call": None,
        }
    )
    assert _runner()._readiness_context_exit_code(
        replace(context, manifest=inconclusive_manifest, result=None)
    ) == 3

    class _TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    terminal = _TTY()
    monkeypatch.setattr(_runner().sys, "stdout", terminal)
    assert _runner().main(["eval-readiness-status", "--run", str(run)]) == 0
    assert terminal.getvalue().splitlines() == [
        "Baseline-locked strict-equivalent: PASS",
        "Historical Protocol 2.2 strict disposition: not supplied",
        "Delivery readiness: HIGH_ASSURANCE",
    ]


def test_readiness_verify_integrity_failure_is_safe_and_exit_five(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs, _ = _support_modules(monkeypatch)
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "readiness-run"
    assert _runner().main(_initialize_arguments(source, run)) == 0
    capsys.readouterr()
    (run / "readiness-input.json").write_bytes(b"{}")
    before = _tree_bytes(run)

    code = _runner().main(["eval-readiness-verify", "--run", str(run)])
    payload = json.loads(capsys.readouterr().out)

    assert code == 5
    assert payload == {
        "baseline_locked_strict_equivalent_disposition": None,
        "delivery_readiness": None,
        "issue_codes": ["READINESS_ARTIFACT_INVALID"],
        "manifest_fingerprint": None,
        "ok": False,
        "protocol_version": "delivery-readiness-v1",
        "result_fingerprint": None,
        "root_hash": None,
        "strict_equivalent_scoring_contract_fingerprint": None,
    }
    assert _tree_bytes(run) == before
