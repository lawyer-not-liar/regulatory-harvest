import asyncio
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import regulatory_harvest.evaluation.attorney_artifacts as attorney_artifacts
from regulatory_harvest.cli import main
from regulatory_harvest.evaluation.attorney_cli import (
    _case_and_capsules_from_fixture,
    _scripted_drafts_from_fixture,
)
from regulatory_harvest.evaluation.attorney_v2_models import EvaluatorResponseV2
from regulatory_harvest.evaluation.attorney_v2_workflow import (
    initialize_evaluation_v2,
    next_evaluator_request_v2,
    submit_evaluator_response_v2,
)
from regulatory_harvest.evaluation.attorney_v21_models import (
    EvaluatorOperationV21,
    EvaluatorRequestV21,
)
from regulatory_harvest.evaluation.attorney_v21_workflow import (
    guarded_submit_evaluator_response_v21,
    initialize_evaluation_v21,
    next_evaluator_request_v21,
)
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    EvaluatorProvenanceV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    EvaluatorOperationV22,
    EvaluatorRequestV22,
)
from regulatory_harvest.evaluation.attorney_v22_requests import (
    COMPILER_CONTRACT_FINGERPRINT_V22,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    initialize_evaluation_v22,
    next_evaluator_request_v22,
    submit_evaluator_response_v22,
)
from regulatory_harvest.evaluation.attorney_workflow import initialize_evaluation
from regulatory_harvest.storage import canonical_json_bytes

FIXTURE = Path(__file__).parents[1] / "fixtures" / "legalbench-mini"
ATTORNEY_FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval"
ATTORNEY_V2_FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval-v2"
ATTORNEY_V21_FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval-v21"
ATTORNEY_V22_FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval-v22"
ROOT = Path(__file__).parents[2]
FULL_PUBLIC_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_PUBLIC_RUNNER = ROOT / "scripts" / "harvest_portable.py"

_LEGACY_FULL_EVAL_HELP_SHA256 = {
    "eval-baseline-init": "d1f1641f4dd8d24505c3ea8d955a620c15f0fc3b574aba898d438ff8fc84db75",
    "eval-baseline-next": "367847de27511bd2a0b54bcd9f81ceb0a913181aaec2e9b04639ccf03406be9c",
    "eval-baseline-submit-safe": "e82544e520debb391b4c07cf6cf042945c6e7e0bad9cbcdc0775cab74168b3be",
    "eval-baseline-status": "eaa96286b94ffeb89456c75eb0898fe16f3afb67ec794e146fb528fdeba36ca5",
    "eval-baseline-verify": "2147611fccb5cda86b572f75fa750cd90d2087011dc566499839890e5fa6f7bf",
    "eval-init": "dcf6a1a94d1bca15211b05be2c0feafdec23e78f8a15b3ca0eaa462e8068e234",
    "eval-next": "4a0abbd80ea3b30feef6d87d8d723f8a81585ba0978f25fac8925e6b20755586",
    "eval-preflight": "5431884971e06354a1d93ef40ddc3079a40017a297f63d3b03cf1fb6843777c8",
    "eval-submit": "0c682dc1314e51da7f9556a901efa195399863674321a78326a01bc029aab922",
    "eval-submit-safe": "ff9d52254e10eb411c669f96c746622ed98d28309254d106cd80a7a89d84bb62",
    "eval-stop-inconclusive": "201dc8b309fb70cfa61f3b77f47d41f1f5b9dacc3debb98e7a10f7efca170d6c",
    "eval-status": "e1a6a403cc702e4b687f25b4057c5c625329dd9254fadae56a894265aeb85b34",
    "eval-verify": "8cc2c3bf81680fb9d096b5eed3642f9eb81ede1407f8f6599c28d84a1e85b460",
    "eval-resume": "6111cdbc830fa23055a6c2e8fee297d876ffe6f28ee7db19e91906ed1a6d9698",
    "eval-qualify-init": "4dc6742d19259eba2f983f088098f02cf165488e16e3dca7265a252b6d56918a",
    "eval-qualify-next": "0793fe4de07b18fb1931cfee9947088bc6477b10d591d04ab2929f7df2e773b5",
    "eval-qualify-submit": "13811d043601e702a4277833300b8bd0619346bb5aace04c6fc2a5a7ee3bdc22",
    "eval-qualify-status": "291e6aaa94a01fca2520afed918cbe16d088abf2812052115654518e304cb6c6",
    "eval-qualify-verify": "e0f30e5393c65fa2bf4d74d825714c70650e9bfe0ff9364d76e967e614ba64a7",
    "eval-gen-init": "b4de50e5aa5ba1290617fc0178a66ad6f0c935d8fc4fb00191a33354afd01707",
    "eval-gen-next": "eb9a0f04f96251c9d9e4a87e53e1bead3c02e097bb9e8e70e0f936a5239ef88c",
    "eval-gen-submit": "50ab154bf1f6cb3ed717e181152c3a0e131b72dacfd8488cbe6edd86e649ae93",
    "eval-gen-status": "76ebdd0b7e6636988323045ec21b60c40250d1e858cbe1f4da64e924ea13abe7",
    "eval-gen-verify": "e5060d62065fe30150b275ccf488efb89775930bdb85b202c670b6f8449160f0",
}


def test_legacy_full_evaluation_help_and_default_protocol_are_byte_stable() -> None:
    for command, expected in _LEGACY_FULL_EVAL_HELP_SHA256.items():
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "attorney_eval_full.py"), command, "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        assert (result.returncode, result.stderr) == (0, b"")
        assert hashlib.sha256(result.stdout).hexdigest() == expected

    import importlib.util

    runner_path = ROOT / "scripts" / "attorney_eval_full.py"
    spec = importlib.util.spec_from_file_location("retained_cli_parser_snapshot", runner_path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    parsed = runner._parser().parse_args(
        ["eval-init", "--case", "case.json", "--run", "run", "--seed-hex", "0" * 64]
    )
    assert parsed.protocol == "2.1"


def test_baseline_scripted_fixture_has_bounded_exhaustion_and_malformed_taxonomy() -> None:
    """Fixture defects stay input defects and never become provider/runtime failures."""
    from regulatory_harvest.evaluation.attorney_baseline_models import (
        BaselineEvaluatorRequestV1,
    )
    from regulatory_harvest.evaluation.attorney_baseline_workflow import (
        BaselineDraftPromptV1,
    )
    from regulatory_harvest.evaluation.attorney_cli import (
        _ScriptedBaselineDraftExhaustedError,
        _ScriptedBaselineDraftFixtureError,
        _ScriptedFixtureBaselineDraftEvaluatorV1,
    )

    with pytest.raises(_ScriptedBaselineDraftFixtureError):
        _ScriptedFixtureBaselineDraftEvaluatorV1(
            {"fixture_type": "local-scripted-drafts-evaluation-baseline-v1", "responses": {}}
        )

    request = BaselineEvaluatorRequestV1(
        operation="baseline_source_review",
        request_fingerprint="0" * 64,
        system_instructions="Return only the strict source-review payload.",
        json_schema={},
        payload={},
    )
    fixture = _ScriptedFixtureBaselineDraftEvaluatorV1(
        {
            "fixture_type": "local-scripted-drafts-evaluation-baseline-v1",
            "responses": [
                {
                    "draft": {"proposals": [], "review_complete": True},
                    "expect": {
                        "attempt": 1,
                        "repair_codes": [],
                        "request_fingerprint": "0" * 64,
                    },
                    "operation": "baseline_source_review",
                }
            ],
        }
    )
    prompt = BaselineDraftPromptV1(request=request, attempt=1)
    assert asyncio.run(fixture.evaluate_draft(prompt)) == {
        "proposals": [],
        "review_complete": True,
    }
    with pytest.raises(_ScriptedBaselineDraftExhaustedError):
        asyncio.run(fixture.evaluate_draft(prompt))


def test_baseline_human_status_is_bounded_and_never_says_pass() -> None:
    """Human status communicates phase and pause without claiming legal substance."""
    from regulatory_harvest.evaluation.attorney_cli import render_baseline_status_human_v1

    rendered = render_baseline_status_human_v1(
        {
            "protocol_version": "evaluation-baseline-v1",
            "phase": "source_review",
            "pending_operation": "baseline_source_review",
            "request_fingerprint": "a" * 64,
            "legal_input_fingerprint": "b" * 64,
            "baseline_fingerprint": None,
            "manifest_fingerprint": "c" * 64,
            "root_hash": "d" * 64,
            "engine_paused": False,
        }
    )

    assert "evaluation-baseline-v1" in rendered
    assert "source_review" in rendered
    assert "PASS" not in rendered
    assert "/private/" not in rendered


def test_eval_cli_runs_user_supplied_synthetic_dataset(
    tmp_path: Path,
    capsys,
) -> None:
    """The CLI must produce a stable status and caller-selected result file."""
    output = tmp_path / "evaluation.json"
    config = tmp_path / "config.json"
    config.write_text('{"method":"fixture","top_k":1}', encoding="utf-8")

    exit_code = main(
        [
            "eval",
            "legalbench-rag",
            "--dataset",
            str(FIXTURE),
            "--predictions",
            str(FIXTURE / "predictions.jsonl"),
            "--output",
            str(output),
            "--config-file",
            str(config),
            "--json",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "cases": 1,
        "macro_f1": 1.0,
        "micro_f1": 1.0,
        "ok": True,
        "output": str(output),
    }
    assert output.exists()


def test_eval_cli_refuses_unacknowledged_non_synthetic_dataset(
    tmp_path: Path,
    capsys,
) -> None:
    """CLI automation must receive a stable terms error instead of an evaluation."""
    dataset = tmp_path / "dataset"
    shutil.copytree(FIXTURE, dataset)
    (dataset / "FIXTURE_LICENSE.md").unlink()

    exit_code = main(
        [
            "eval",
            "legalbench-rag",
            "--dataset",
            str(dataset),
            "--predictions",
            str(dataset / "predictions.jsonl"),
            "--output",
            str(tmp_path / "result.json"),
            "--json",
        ]
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "upstream_terms_not_accepted",
        "ok": False,
    }


def test_eval_help_states_dataset_is_user_supplied() -> None:
    """Help must not imply that Harvest downloads or bundles benchmark data."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "regulatory_harvest.cli",
            "eval",
            "legalbench-rag",
            "--help",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "user-supplied" in result.stdout


def test_attorney_eval_cli_runs_local_scripted_synthetic_case(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    output = tmp_path / "attorney-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    )

    assert status == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "COMPLETED"
    assert (
        json.loads((output / "result.json").read_text())["reports"][0]["reconciliation"][
            "absolute_disposition"
        ]
        == "PASS"
    )


def test_protocol_21_completes_strict_local_scripted_sequence(tmp_path: Path, capsys) -> None:
    """The public fixture is bound to the complete v2.1 request sequence."""
    fixture = _scripted_fixture_copy(tmp_path)
    output = tmp_path / "strict-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    )

    assert status == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["terminal_state"] == "COMPLETED"
    assert [report["absolute_disposition"] for report in receipt["reports"]] == ["PASS"]
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert [call["operation"] for call in manifest["calls"]] == [
        "source_review",
        "source_audit",
        "ordinary_grade_fragment",
        "ordinary_grade_fragment",
    ]


def test_protocol_21_public_run_reports_verified_mechanical_inconclusive(
    tmp_path: Path, capsys
) -> None:
    """A valid result-less mechanical terminal is public inconclusive, not integrity-invalid."""
    fixture = _mechanically_invalid_protocol_21_fixture_copy(tmp_path)
    output = tmp_path / "mechanical-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    )

    assert status == 3
    assert json.loads(capsys.readouterr().out) == {
        "all_issue_codes": [],
        "comparative_disposition": None,
        "judge_mode": "local-scripted-fixture",
        "manifest_root": json.loads((output / "run-manifest.json").read_text())[
            "manifest_fingerprint"
        ],
        "reports": [],
        "run_path": str(output),
        "terminal_state": "INCONCLUSIVE_MECHANICAL",
    }
    assert not (output / "result.json").exists()


def test_protocol_21_public_verify_reports_verified_mechanical_inconclusive(
    tmp_path: Path, capsys
) -> None:
    """Verification preserves a valid result-less mechanical terminal without writing a result."""
    fixture = _mechanically_invalid_protocol_21_fixture_copy(tmp_path)
    output = tmp_path / "mechanical-verify"
    assert main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(output),
            "--json",
        ]
    ) == 3
    capsys.readouterr()
    before = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file()
    }

    status = main(["eval", "attorney", "verify", "--output", str(output), "--json"])

    assert status == 3
    assert json.loads(capsys.readouterr().out) == {
        "all_issue_codes": [],
        "comparative_disposition": None,
        "judge_mode": "verification-only",
        "manifest_root": json.loads((output / "run-manifest.json").read_text())[
            "manifest_fingerprint"
        ],
        "reports": [],
        "run_path": str(output),
        "terminal_state": "INCONCLUSIVE_MECHANICAL",
    }
    assert {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file()
    } == before
    assert not (output / "result.json").exists()


def test_protocol_21_fragmented_fictional_fixtures_cover_stable_and_sensitive_replay(
    tmp_path: Path, capsys
) -> None:
    """Committed strict scripts cover the public fragmented lifecycle and replay."""
    stable = ATTORNEY_V21_FIXTURE / "stable"
    stable_run = tmp_path / "stable-run"
    stable_status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(stable / "case.json"),
            "--scripted-responses",
            str(stable / "responses" / "scripted-responses.json"),
            "--output",
            str(stable_run),
            "--json",
        ]
    )
    assert stable_status == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "COMPLETED"
    stable_manifest = json.loads((stable_run / "run-manifest.json").read_text())
    operations = [call["operation"] for call in stable_manifest["calls"]]
    assert operations.count("source_referee_fragment") == 3
    assert operations.count("ordinary_grade_fragment") == 4
    assert operations.count("contested_grade_fragment") == 2
    assert (stable_run / "responses" / "source-audit.json").is_file()
    before_verify = _run_snapshot(stable_run)
    assert main(["eval", "attorney", "verify", "--output", str(stable_run), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "COMPLETED"
    assert _run_snapshot(stable_run) == before_verify

    sensitive = ATTORNEY_V21_FIXTURE / "sensitive"
    sensitive_run = tmp_path / "sensitive-run"
    assert (
        main(
            [
                "eval",
                "attorney",
                "run",
                "--case",
                str(sensitive / "case.json"),
                "--scripted-responses",
                str(sensitive / "responses" / "scripted-responses.json"),
                "--output",
                str(sensitive_run),
                "--json",
            ]
        )
        == 3
    )
    sensitive_result = json.loads(capsys.readouterr().out)
    assert sensitive_result["reports"][0]["absolute_disposition"] == "INCONCLUSIVE"
    sensitive_artifact = json.loads((sensitive_run / "result.json").read_text())
    assert (
        "OUTCOME_SENSITIVE_BASELINE_DISPUTE"
        in sensitive_artifact["reports"][0]["sensitivity"]["reason_codes"]
    )
    assert main(["eval", "attorney", "verify", "--output", str(sensitive_run), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "INCONCLUSIVE"


def test_attorney_cli_requires_explicit_local_scripted_fixture(tmp_path: Path, capsys) -> None:
    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(ATTORNEY_FIXTURE / "case.json"),
            "--output",
            str(tmp_path / "run"),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "scripted_fixture_required",
        "ok": False,
    }


def test_protocol_21_scripted_fixture_adapter_binds_operation_and_request_fingerprint() -> None:
    """Fixture-only 2.1 responses cannot be replayed onto another pending request."""
    from regulatory_harvest.evaluation.attorney_cli import _ScriptedFixtureEvaluatorV21

    evaluator = _ScriptedFixtureEvaluatorV21(
        {
            "fixture_type": "local-scripted",
            "responses": [
                {
                    "expect": {"request_fingerprint": "a" * 64},
                    "operation": "source_review",
                    "payload": {},
                }
            ],
        }
    )
    request = EvaluatorRequestV21(
        schema_version="2.1",
        operation=EvaluatorOperationV21.SOURCE_REVIEW,
        request_fingerprint="b" * 64,
        system_instructions="Return the requested fixture response.",
        payload={},
        json_schema={"type": "object"},
        safe_metadata={},
    )

    with pytest.raises(ValueError, match="request mismatched"):
        import asyncio

        asyncio.run(evaluator.evaluate(request))


def _scripted_fixture_copy(tmp_path: Path) -> Path:
    fixture = tmp_path / "attorney-eval"
    shutil.copytree(ATTORNEY_FIXTURE, fixture)
    _write_protocol_21_scripted_responses(fixture)
    return fixture


def _fragmented_v21_fixture_copy(tmp_path: Path, scenario: str) -> Path:
    fixture = tmp_path / f"attorney-eval-v21-{scenario}"
    shutil.copytree(ATTORNEY_V21_FIXTURE / scenario, fixture)
    return fixture


def _run_snapshot(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def _write_fragmented_v21_scripted_responses(
    fixture: Path, *, outcome_changing: bool
) -> None:
    """Create responses from each current request; no stale fingerprint is accepted."""
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = fixture / "probe"
    initialize_evaluation_v21(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    responses: list[dict[str, object]] = []
    while (request := next_evaluator_request_v21(probe)) is not None:
        payload = _fragmented_v21_payload(
            request.model_dump(mode="json"), outcome_changing=outcome_changing
        )
        responses.append(
            {
                "expect": {"request_fingerprint": request.request_fingerprint},
                "operation": request.operation.value,
                "payload": payload,
            }
        )
        submission = guarded_submit_evaluator_response_v21(
            probe,
            {
                "schema_version": "2.1",
                "operation": request.operation,
                "request_fingerprint": request.request_fingerprint,
                "provider_name": "local-scripted-fixture",
                "model_name": "no-provider",
                "judge_isolation": "scripted_fixture",
                "payload": payload,
            },
        )
        assert submission.accepted, (request.operation, submission.preflight)
    (fixture / "responses" / "scripted-responses.json").write_bytes(
        canonical_json_bytes({"fixture_type": "local-scripted", "responses": responses})
    )


def _fragmented_v21_payload(
    request: dict[str, object], *, outcome_changing: bool
) -> dict[str, object]:
    operation = request["operation"]
    payload = request["payload"]
    assert isinstance(payload, dict)
    if operation == "source_review":
        source_record = payload["source_record"]
        assert isinstance(source_record, dict)
        sources = source_record["sources"]
        assert isinstance(sources, list) and len(sources) == 1
        source = sources[0]
        assert isinstance(source, dict)
        source_id = source["source_id"]
        source_text = source["normalized_text"]
        assert isinstance(source_id, str) and isinstance(source_text, str)
        return {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": f"Fictional duty {index} applies to a covered operator.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [{"source_id": source_id, "quote": source_text}],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": f"The fictional rule supports duty {index}.",
                }
                for index in range(1, 2 if outcome_changing else 9)
            ],
        }
    if operation == "source_audit":
        source_record = payload["source_record"]
        assert isinstance(source_record, dict)
        sources = source_record["sources"]
        assert isinstance(sources, list) and len(sources) == 1
        source = sources[0]
        assert isinstance(source, dict)
        source_id = source["source_id"]
        source_text = source["normalized_text"]
        assert isinstance(source_id, str) and isinstance(source_text, str)
        correction = {
            "statement": "Corrected fictional duty two applies to a covered operator.",
            "kind": "obligation",
            "importance": "critical",
            "passages": [{"source_id": source_id, "quote": source_text}],
            "dependency": None,
            "confidence": "clear",
            "rationale": "The audit corrects the second fictional duty.",
        }
        contested_correction = {
            **correction,
            "statement": "Corrected fictional duty three applies to a covered operator.",
            "rationale": "The audit supplies the competing third fictional duty.",
        }
        if outcome_changing:
            return {
                "schema_version": "2.1",
                "concerns": [
                    {
                        "target_proposal_ref": "P0001",
                        "concern_type": "ambiguity",
                        "passages": [{"source_id": source_id, "quote": source_text}],
                        "explanation": "The only fictional duty remains ambiguous.",
                        "correction": None,
                    }
                ],
            }
        return {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": source_id, "quote": source_text}],
                    "explanation": "The first fictional duty is disputed.",
                    "correction": None,
                },
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": source_id, "quote": source_text}],
                    "explanation": "The second fictional duty needs correction.",
                    "correction": correction,
                },
                {
                    "target_proposal_ref": "P0003",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": source_id, "quote": source_text}],
                    "explanation": "The third fictional duty remains ambiguous.",
                    "correction": contested_correction,
                },
            ],
        }
    if operation == "source_referee_fragment":
        metadata = request["safe_metadata"]
        assert isinstance(metadata, dict)
        decisions = (
            {"D0001": ("unresolved", "SOURCE_AMBIGUITY")}
            if outcome_changing
            else {
                "D0001": ("accept_reviewer", None),
                "D0002": ("accept_auditor", None),
                "D0003": ("unresolved", "SOURCE_AMBIGUITY"),
            }
        )
        decision, unresolved_reason = decisions[metadata["dispute_id"]]
        disputes = payload["material_disputes"]
        assert isinstance(disputes, list) and len(disputes) == 1
        dispute = disputes[0]
        assert isinstance(dispute, dict)
        evidence = dispute["evidence"]
        assert isinstance(evidence, list) and evidence
        first_evidence = evidence[0]
        assert isinstance(first_evidence, dict)
        return {
            "schema_version": "2.1",
            "decision": decision,
            "unresolved_reason": unresolved_reason,
            "evidence_refs": [first_evidence["evidence_ref"]],
            "rationale": "The fictional closed record supports this referee result.",
        }
    report_text = payload["report_text"]
    assert isinstance(report_text, str)
    if operation == "ordinary_grade_fragment":
        requirements = payload["requirements"]
        assert isinstance(requirements, list)
        return {
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
                    "report_passages": [report_text],
                    "rationale": "The fictional report states the ordinary requirement.",
                    "omission": None,
                }
                for requirement in requirements
            ],
            "rationale": "The fictional report satisfies this bounded batch.",
        }
    assert operation == "contested_grade_fragment"
    contested = payload["contested_requirement"]
    assert isinstance(contested, dict)
    auditor_disposition = "not_met" if outcome_changing else "met"
    return {
        "schema_version": "2.1",
        "anonymous_label": payload["anonymous_label"],
        "grader_lane": payload["grader_lane"],
        "contested_requirement_id": contested["contested_requirement_id"],
        "baseline_fingerprint": payload["baseline_fingerprint"],
        "report_fingerprint": payload["report_fingerprint"],
        "reviewer_alternative_grade": {
            "disposition": "met",
            "report_passages": [report_text],
            "rationale": "The fictional report satisfies the reviewer alternative.",
        },
        "auditor_alternative_grade": {
            "disposition": auditor_disposition,
            "report_passages": [report_text],
            "rationale": "The fictional report distinguishes the auditor alternative.",
        },
        "ambiguity_disposition": (
            "omitted" if outcome_changing and payload["grader_lane"] == 2 else "acknowledged"
        ),
        "rationale": "The fictional report evaluates the contested requirement.",
    }


def _mechanically_invalid_protocol_21_fixture_copy(tmp_path: Path) -> Path:
    """Return two exact source-review retries that fail only payload validation."""
    fixture = _scripted_fixture_copy(tmp_path)
    response_path = fixture / "responses" / "scripted-responses.json"
    fixture_data = json.loads(response_path.read_text(encoding="utf-8"))
    first = fixture_data["responses"][0]
    assert first["operation"] == "source_review"
    invalid = {
        "expect": first["expect"],
        "operation": first["operation"],
        "payload": {"schema_version": "2.1"},
    }
    retry_invalid = copy.deepcopy(invalid)
    retry_invalid["payload"] = {"schema_version": "2.1", "proposals": "invalid"}
    fixture_data["responses"] = [invalid, retry_invalid]
    _write_canonical(response_path, fixture_data)
    return fixture


def _write_protocol_21_scripted_responses(fixture: Path) -> None:
    """Bind a public synthetic 2.1 fixture to the exact requests it will receive."""
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = fixture / "probe"
    initialize_evaluation_v21(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    responses: list[dict[str, object]] = []
    response_index = 0
    while (request := next_evaluator_request_v21(probe)) is not None:
        response_index += 1
        payload = _v21_semantic_payload(request.model_dump(mode="json"), response_index)
        responses.append(
            {
                "expect": {"request_fingerprint": request.request_fingerprint},
                "operation": request.operation.value,
                "payload": payload,
            }
        )
        submission = guarded_submit_evaluator_response_v21(
            probe,
            {
                "schema_version": "2.1",
                "operation": request.operation,
                "request_fingerprint": request.request_fingerprint,
                "provider_name": "local-scripted-fixture",
                "model_name": "no-provider",
                "judge_isolation": "scripted_fixture",
                "payload": payload,
            },
        )
        assert submission.accepted, (request.operation, submission.preflight)
    (fixture / "responses" / "scripted-responses.json").write_bytes(
        canonical_json_bytes({"fixture_type": "local-scripted", "responses": responses})
    )


def _v21_semantic_payload(request: dict[str, object], response_index: int) -> dict[str, object]:
    operation = request["operation"]
    payload = request["payload"]
    assert isinstance(payload, dict)
    if operation == "source_review":
        source_record = payload["source_record"]
        assert isinstance(source_record, dict)
        sources = source_record["sources"]
        assert isinstance(sources, list) and len(sources) == 1
        source = sources[0]
        assert isinstance(source, dict)
        return {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": "A covered operator must file a registry notice within 10 days.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {"source_id": source["source_id"], "quote": source["normalized_text"]}
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic operative text states the filing duty.",
                }
            ],
        }
    if operation == "source_audit":
        return {"schema_version": "2.1", "concerns": []}
    assert operation == "ordinary_grade_fragment"
    requirements = payload["requirements"]
    report_text = payload["report_text"]
    assert isinstance(requirements, list) and isinstance(report_text, str)
    return {
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
                "report_passages": [
                    "A covered operator must file a registry notice within 10 days "
                    "and retain proof of filing."
                ],
                "rationale": f"The report states the requirement ({response_index}).",
                "omission": None,
            }
            for requirement in requirements
        ],
        "rationale": "The report satisfies this bounded batch.",
    }


def _v2_fixture_copy(tmp_path: Path) -> Path:
    """Copy complete deterministic fictional generation capsules without rebuilding them."""
    fixture = tmp_path / "attorney-eval-v2"
    shutil.copytree(ATTORNEY_V2_FIXTURE, fixture)
    return fixture


def _write_v2_scripted_responses(fixture: Path) -> None:
    """Freeze strictly request-bound public semantic evaluator responses."""
    case, capsule_paths = _case_and_capsules_from_fixture(fixture / "case.json", root=fixture)
    probe = fixture / "probe"
    initialize_evaluation_v2(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    responses: list[dict[str, object]] = []
    response_index = 0
    while (request := next_evaluator_request_v2(probe)) is not None:
        response_index += 1
        request_data = request.model_dump(mode="json")
        payload = _v2_semantic_payload(request_data, response_index)
        responses.append(
            {
                "expect": {"request_fingerprint": request.request_fingerprint},
                "operation": request.operation.value,
                "payload": payload,
            }
        )
        submit_evaluator_response_v2(
            probe,
            EvaluatorResponseV2(
                operation=request.operation,
                request_fingerprint=request.request_fingerprint,
                provider_name="local-scripted-fixture",
                model_name="no-provider",
                judge_isolation="scripted_fixture",
                payload=payload,
            ),
        )
    (fixture / "scripted-responses.json").write_bytes(
        canonical_json_bytes({"fixture_type": "local-scripted", "responses": responses})
    )


def _v2_semantic_payload(request: dict[str, object], response_index: int) -> dict[str, object]:
    operation = request["operation"]
    payload = request["payload"]
    assert isinstance(payload, dict)
    source_id = "fictional-source"
    source_sentence = "A covered operator must file a notice by 10 June."
    enforcement_statement = (
        "The fictional bureau may issue an order, and a violation may result in a civil penalty."
    )
    proposals = [
        {
            "statement": "A covered operator must file a notice by June.",
            "kind": "obligation",
            "importance": "critical",
            "passages": [{"source_id": source_id, "quote": source_sentence}],
            "dependency": None,
            "confidence": "clear",
            "rationale": "The fictional rule imposes the filing duty.",
        },
        {
            "statement": "The filing duty does not apply during a declared exercise.",
            "kind": "exception",
            "importance": "critical",
            "passages": [
                {
                    "source_id": source_id,
                    "quote": "The filing duty does not apply during a declared exercise.",
                }
            ],
            "dependency": None,
            "confidence": "clear",
            "rationale": "The source states a declared-exercise exception.",
        },
        {
            "statement": enforcement_statement,
            "kind": "enforcement",
            "importance": "material",
            "passages": [
                {
                    "source_id": source_id,
                    "quote": enforcement_statement,
                }
            ],
            "dependency": None,
            "confidence": "clear",
            "rationale": "The source supplies the fictional enforcement consequence.",
        },
        {
            "statement": "The source does not establish any filing fee.",
            "kind": "gap",
            "importance": "material",
            "passages": [
                {"source_id": source_id, "quote": "The source does not establish any filing fee."}
            ],
            "dependency": None,
            "confidence": "clear",
            "rationale": "The source explicitly identifies the fictional fee gap.",
        },
    ]
    if operation == "source_review":
        return {"schema_version": "2.0", "proposals": proposals}
    if operation == "source_audit":
        return {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": source_id, "quote": source_sentence}],
                    "explanation": "The deadline must retain the source's exact date.",
                    "correction": {
                        **proposals[0],
                        "statement": "A covered operator must file a notice by 10 June.",
                    },
                }
            ],
        }
    if operation == "source_referee":
        disputes = payload["material_disputes"]
        assert isinstance(disputes, list) and len(disputes) == 1
        dispute = disputes[0]
        assert isinstance(dispute, dict)
        return {
            "schema_version": "2.0",
            "decisions": [
                {
                    "dispute_id": dispute["dispute_id"],
                    "decision": "accept_auditor",
                    "passages": [{"source_id": source_id, "quote": source_sentence}],
                    "rationale": "The explicit fictional date supports the corrected requirement.",
                }
            ],
        }
    assert operation == "grade_report"
    report = payload["anonymous_report"]
    requirements = payload["requirements"]
    metadata = request["safe_metadata"]
    assert (
        isinstance(report, dict) and isinstance(requirements, list) and isinstance(metadata, dict)
    )
    report_text = report["report_text"]
    assert isinstance(report_text, str)
    is_complete_report = "does not establish any filing fee" in report_text
    report_passages = {
        source_sentence: source_sentence,
        "The filing duty does not apply during a declared exercise.": (
            "The duty does not apply during a declared exercise."
        ),
        enforcement_statement: (
            "The fictional bureau may issue an order and a violation may result in a civil penalty."
        ),
        "The source does not establish any filing fee.": (
            "The source does not establish any filing fee."
        ),
    }
    grades = []
    for requirement in requirements:
        assert isinstance(requirement, dict)
        statement = requirement["statement"]
        assert isinstance(statement, str)
        grades.append(
            {
                "requirement_id": requirement["requirement_id"],
                "disposition": "met" if is_complete_report else "not_met",
                "report_passages": [report_passages[statement]] if is_complete_report else [],
                "rationale": (
                    "The complete fictional report states this supported requirement "
                    f"(observation {response_index})."
                    if is_complete_report
                    else "The comparison report omits this material fictional requirement "
                    f"(observation {response_index})."
                ),
                "omission": None if is_complete_report else statement,
            }
        )
    return {
        "schema_version": "2.0",
        "anonymous_label": report["anonymous_label"],
        "baseline_fingerprint": metadata["baseline_fingerprint"],
        "requirement_grades": grades,
        "unsupported_assertions": [],
        "baseline_defect": None,
    }


def _semantic_payload(request: dict[str, object], response_index: int) -> dict[str, object]:
    operation = request["operation"]
    payload = request["payload"]
    assert isinstance(payload, dict)
    if operation == "source_review":
        source_record = payload["source_record"]
        assert isinstance(source_record, dict)
        sources = source_record["sources"]
        assert isinstance(sources, list) and len(sources) == 1
        source = sources[0]
        assert isinstance(source, dict)
        return {
            "schema_version": "2.0",
            "proposals": [
                {
                    "statement": "A covered operator must file the registry notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {"source_id": source["source_id"], "quote": source["normalized_text"]}
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic operative text states the filing duty.",
                }
            ],
        }
    if operation == "source_audit":
        return {"schema_version": "2.0", "concerns": []}
    assert operation == "grade_report"
    baseline_fingerprint = request["safe_metadata"]
    assert isinstance(baseline_fingerprint, dict)
    report = payload["anonymous_report"]
    requirements = payload["requirements"]
    assert isinstance(report, dict) and isinstance(requirements, list)
    return {
        "schema_version": "2.0",
        "anonymous_label": report["anonymous_label"],
        "baseline_fingerprint": baseline_fingerprint["baseline_fingerprint"],
        "requirement_grades": [
            {
                "requirement_id": requirement["requirement_id"],
                "disposition": "met",
                "report_passages": [report["report_text"]],
                "rationale": f"Synthetic grader {response_index} found the requirement stated.",
                "omission": None,
            }
            for requirement in requirements
        ],
        "unsupported_assertions": [],
        "baseline_defect": None,
    }


def _write_canonical(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


_V22_PROVENANCE = EvaluatorProvenanceV22(
    provider_name="local-scripted-fixture",
    model_name="no-provider",
    judge_isolation="scripted_fixture",
)


def _v22_draft(
    request: EvaluatorRequestV22,
    *,
    disposition: str = "met",
    empty_sources: bool = False,
) -> dict[str, object]:
    if request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        return {
            "proposals": []
            if empty_sources
            else [
                {
                    "statement": "A covered operator must file a registry notice within 10 days.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {
                            "source_id": "synthetic-rule-1-source",
                            "quote": (
                                "A covered operator must file a registry notice within 10 days"
                            ),
                        }
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The source states the filing duty directly.",
                }
            ],
            "review_complete": True,
        }
    if request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        return {"concerns": [], "audit_complete": True}
    assert request.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT
    requirements = request.payload["requirements"]
    report_text = request.payload["report_text"]
    assert isinstance(requirements, list) and isinstance(report_text, str)
    return {
        "requirement_grades": [
            {
                "requirement_ordinal": ordinal,
                "disposition": disposition,
                "report_passages": [] if disposition == "not_met" else [report_text],
                "rationale": "The report was graded against the issued requirement.",
                "omission": "The required duty is absent."
                if disposition == "not_met"
                else None,
            }
            for ordinal, _ in enumerate(requirements, 1)
        ],
        "rationale": "Every issued requirement was graded.",
    }


def _v22_script_from_run(
    run: Path,
    path: Path,
    *,
    disposition: str = "met",
    empty_sources: bool = False,
) -> None:
    responses: list[dict[str, object]] = []
    while (request := next_evaluator_request_v22(run)) is not None:
        draft = _v22_draft(
            request,
            disposition=disposition,
            empty_sources=empty_sources,
        )
        responses.append(
            {
                "draft": draft,
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": request.request_fingerprint,
                },
                "operation": request.operation.value,
            }
        )
        compiled = compile_evaluator_draft_v22(request, draft, _V22_PROVENANCE)
        assert isinstance(compiled, CompiledDraftV22)
        submit_evaluator_response_v22(run, compiled.response)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_canonical(
        path,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses},
    )


def _v22_script_for_new_run(
    fixture: Path,
    tmp_path: Path,
    *,
    disposition: str = "met",
    empty_sources: bool = False,
) -> Path:
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = tmp_path / f"probe-{disposition}-{'empty' if empty_sources else 'substantive'}"
    initialize_evaluation_v22(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    path = fixture / "responses" / f"v22-{disposition}-{'empty' if empty_sources else 'full'}.json"
    _v22_script_from_run(
        probe,
        path,
        disposition=disposition,
        empty_sources=empty_sources,
    )
    return path


@pytest.mark.parametrize(
    "mutation", ["outside", "noncanonical", "operation", "duplicate", "exhausted"]
)
def test_attorney_cli_rejects_unsafe_or_incomplete_local_fixture(
    tmp_path: Path,
    capsys,
    mutation: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = fixture / "responses" / "scripted-responses.json"
    data = json.loads(responses.read_text(encoding="utf-8"))
    response_path = responses
    if mutation == "outside":
        response_path = tmp_path / "outside.json"
        _write_canonical(response_path, data)
    elif mutation == "noncanonical":
        responses.write_text(responses.read_text(encoding="utf-8") + " ", encoding="utf-8")
    elif mutation == "operation":
        data["responses"][0]["operation"] = "build_ledger"
        _write_canonical(responses, data)
    elif mutation == "duplicate":
        data["responses"].append(copy.deepcopy(data["responses"][0]))
        _write_canonical(responses, data)
    else:
        data["responses"].pop()
        _write_canonical(responses, data)

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(response_path),
            "--output",
            str(tmp_path / "run"),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }


def test_attorney_cli_rejects_an_intermediate_fixture_symlink(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    retained = fixture / "retained-responses"
    (fixture / "responses").replace(retained)
    try:
        (fixture / "responses").symlink_to(retained, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"fixture symlinks are unavailable: {error}")

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(tmp_path / "run"),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }


def test_attorney_cli_rejects_a_fixture_file_replaced_during_read(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case_path = fixture / "case.json"
    original_read_all = attorney_artifacts._read_all
    replaced = False

    def replace_case_then_read(descriptor: int) -> bytes:
        nonlocal replaced
        if not replaced:
            replaced = True
            case_path.replace(fixture / "case.replaced.json")
            case_path.write_text("{}\n", encoding="utf-8")
        return original_read_all(descriptor)

    monkeypatch.setattr(attorney_artifacts, "_read_all", replace_case_then_read)

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(case_path),
            "--scripted-responses",
            str(fixture / "responses" / "scripted-responses.json"),
            "--output",
            str(tmp_path / "run"),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }


def test_attorney_cli_rejects_a_nonsemantic_scripted_response(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = fixture / "responses" / "scripted-responses.json"
    data = json.loads(responses.read_text(encoding="utf-8"))
    data["responses"][0]["payload"] = {"checks": []}
    _write_canonical(responses, data)

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(tmp_path / "invalid-run"),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }


def test_attorney_cli_failed_required_candidate_is_exit_four(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = fixture / "responses" / "scripted-responses.json"
    data = json.loads(responses.read_text(encoding="utf-8"))
    for response in data["responses"][-2:]:
        response["payload"]["requirement_grades"][0].update(
            disposition="not_met",
            report_passages=[],
            omission="The synthetic report omitted this critical requirement.",
        )
    _write_canonical(responses, data)

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(tmp_path / "failed-run"),
            "--json",
        ]
    )

    assert status == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["reports"][0]["absolute_disposition"] == "FAIL"
    assert "CRITICAL_RECALL_BELOW_FLOOR" in payload["all_issue_codes"]


def test_attorney_verify_is_read_only_and_returns_exit_five_for_tampering(
    tmp_path: Path,
    capsys,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    output = tmp_path / "attorney-run"
    assert (
        main(
            [
                "eval",
                "attorney",
                "run",
                "--case",
                str(fixture / "case.json"),
                "--scripted-responses",
                str(fixture / "responses" / "scripted-responses.json"),
                "--output",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    manifest = output / "run-manifest.json"
    before_verification = manifest.read_bytes()
    assert main(["eval", "attorney", "verify", "--output", str(output), "--json"]) == 0
    assert manifest.read_bytes() == before_verification
    verification = json.loads(capsys.readouterr().out)
    assert verification["terminal_state"] == "COMPLETED"
    assert verification["reports"] == [
        {
            "absolute_disposition": "PASS",
            "reason_codes": [],
        }
    ]
    assert verification["comparative_disposition"] is None
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    before = manifest.read_bytes()

    status = main(["eval", "attorney", "verify", "--output", str(output), "--json"])

    assert status == 5
    assert manifest.read_bytes() == before
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_integrity_invalid",
        "ok": False,
    }


@pytest.mark.parametrize(("disposition", "expected_exit"), [("met", 0), ("not_met", 4)])
def test_protocol_22_attorney_run_maps_completed_public_outcomes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    disposition: str,
    expected_exit: int,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = _v22_script_for_new_run(
        fixture,
        tmp_path,
        disposition=disposition,
    )
    run = tmp_path / f"v22-{disposition}"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == expected_exit
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal_state"] == "COMPLETED"
    assert payload["reports"][0]["absolute_disposition"] == (
        "PASS" if disposition == "met" else "FAIL"
    )
    assert "run_path" not in payload
    assert json.loads((run / "run-manifest.json").read_bytes())["protocol_version"] == "2.2"
    accepted_responses = [
        json.loads(path.read_bytes()) for path in sorted((run / "responses").glob("*.json"))
    ]
    assert accepted_responses
    assert {
        (
            response["provider_name"],
            response["model_name"],
            response["judge_isolation"],
        )
        for response in accepted_responses
    } == {("local-scripted-fixture", "no-provider", "scripted_fixture")}


def test_protocol_22_attorney_run_accepts_one_bad_draft_then_substantive_inconclusive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = tmp_path / "one-bad-probe"
    initialize_evaluation_v22(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    request = next_evaluator_request_v22(probe)
    assert request is not None
    valid_review = _v22_draft(request, empty_sources=True)
    compiled = compile_evaluator_draft_v22(request, valid_review, _V22_PROVENANCE)
    assert isinstance(compiled, CompiledDraftV22)
    submit_evaluator_response_v22(probe, compiled.response)
    audit_request = next_evaluator_request_v22(probe)
    assert audit_request is not None
    responses = fixture / "responses" / "v22-one-bad.json"
    _write_canonical(
        responses,
        {
            "fixture_type": "local-scripted-drafts-v2.2",
            "responses": [
                {
                    "draft": {"malformed": "private-rejected-draft"},
                    "expect": {
                        "attempt": 1,
                        "clarification_codes": [],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                },
                {
                    "draft": valid_review,
                    "expect": {
                        "attempt": 2,
                        "clarification_codes": ["SUBSTANCE_MISSING"],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                },
                {
                    "draft": _v22_draft(audit_request, empty_sources=True),
                    "expect": {
                        "attempt": 1,
                        "clarification_codes": [],
                        "request_fingerprint": audit_request.request_fingerprint,
                    },
                    "operation": audit_request.operation.value,
                },
            ],
        },
    )

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(tmp_path / "one-bad-run"),
            "--json",
        ]
    )

    assert status == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["terminal_state"] == "INCONCLUSIVE"
    assert payload["reports"][0]["reason_codes"] == [
        "BASELINE_EVIDENCE_INSUFFICIENT"
    ]
    assert "INCONCLUSIVE_MECHANICAL" not in json.dumps(payload)


def test_protocol_22_public_run_pauses_and_resumes_same_pending_request(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = tmp_path / "pause-probe"
    initialize_evaluation_v22(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    request = next_evaluator_request_v22(probe)
    assert request is not None
    paused_responses = fixture / "responses" / "v22-two-bad.json"
    _write_canonical(
        paused_responses,
        {
            "fixture_type": "local-scripted-drafts-v2.2",
            "responses": [
                {
                    "draft": {"malformed": "first-private-rejected-draft"},
                    "expect": {
                        "attempt": 1,
                        "clarification_codes": [],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                },
                {
                    "draft": {"malformed": "second-private-rejected-draft"},
                    "expect": {
                        "attempt": 2,
                        "clarification_codes": ["SUBSTANCE_MISSING"],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                },
            ],
        },
    )
    run = tmp_path / "paused-run"

    paused = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(paused_responses),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert paused == 6
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_engine_paused",
        "ok": False,
        "pending_call": "source-review-fragment-0001",
    }
    pending_path = run / "requests" / "source-review-0001.json"
    request_before = pending_path.read_bytes()
    assert not (run / "result.json").exists()

    continuation_probe = tmp_path / "continuation-probe"
    shutil.copytree(run, continuation_probe)
    continuation = fixture / "responses" / "v22-continuation.json"
    _v22_script_from_run(
        continuation_probe,
        continuation,
        empty_sources=True,
    )
    resumed = main(
        [
            "eval",
            "attorney",
            "resume",
            "--output",
            str(run),
            "--scripted-responses",
            str(continuation),
            "--json",
        ]
    )

    assert resumed == 3
    assert pending_path.read_bytes() == request_before
    result = json.loads(capsys.readouterr().out)
    assert result["terminal_state"] == "INCONCLUSIVE"
    manifest = json.loads((run / "run-manifest.json").read_bytes())
    assert [call["call_id"] for call in manifest["calls"]].count("source-review-0001") == 1


def _run_public_v22_fixture_command(
    runner: Path,
    *,
    portable: bool,
    args: list[str],
) -> subprocess.CompletedProcess[str]:
    python_args = [sys.executable]
    if portable:
        python_args.extend(("-I", "-S"))
    return subprocess.run(
        [*python_args, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _committed_v22_fixture_lifecycle(
    fixture: Path,
    run: Path,
    *,
    runner: Path,
    portable: bool,
    initial_script: str,
    resume_script: str | None = None,
) -> tuple[list[tuple[int, str, str]], dict[str, bytes], dict[str, object]]:
    transcript: list[tuple[int, str, str]] = []

    def command(*args: str) -> subprocess.CompletedProcess[str]:
        completed = _run_public_v22_fixture_command(
            runner,
            portable=portable,
            args=list(args),
        )
        transcript.append((completed.returncode, completed.stdout, completed.stderr))
        return completed

    initialized = command(
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(fixture / "case.json"),
        "--run",
        str(run),
        "--seed-hex",
        "0" * 64,
    )
    assert initialized.returncode == 0, initialized.stderr
    pending_before = command("eval-next", "--run", str(run))
    assert pending_before.returncode == 0, pending_before.stderr
    before_initial = _run_snapshot(run)
    initial = command(
        "eval-resume",
        "--run",
        str(run),
        "--scripted-responses",
        str(fixture / "responses" / initial_script),
    )
    if resume_script is None:
        assert initial.returncode == 0, initial.stderr or initial.stdout
    else:
        assert initial.returncode == 6, initial.stderr or initial.stdout
        assert _run_snapshot(run) == before_initial
        pending_after = command("eval-next", "--run", str(run))
        assert pending_after.returncode == 0, pending_after.stderr
        assert pending_after.stdout == pending_before.stdout
        verified_pending = command("eval-verify", "--run", str(run))
        assert verified_pending.returncode == 0, verified_pending.stderr
        assert _run_snapshot(run) == before_initial
        resumed = command(
            "eval-resume",
            "--run",
            str(run),
            "--scripted-responses",
            str(fixture / "responses" / resume_script),
        )
        assert resumed.returncode == 0, resumed.stderr or resumed.stdout

    terminal_tree = _run_snapshot(run)
    status = command("eval-status", "--run", str(run))
    assert status.returncode == 0, status.stderr
    verified = command("eval-verify", "--run", str(run))
    assert verified.returncode == 0, verified.stderr
    assert _run_snapshot(run) == terminal_tree
    result = json.loads((run / "result.json").read_bytes())
    assert isinstance(result, dict)
    return transcript, terminal_tree, result


def _accepted_v22_operations(run: Path) -> tuple[Counter[str], set[str]]:
    operations: Counter[str] = Counter()
    referee_decisions: set[str] = set()
    for path in sorted(run.rglob("*.json")):
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict) or value.get("schema_version") != "2.2":
            continue
        operation = value.get("operation")
        if not isinstance(operation, str) or "provider_name" not in value:
            continue
        operations[operation] += 1
        if operation == "source_referee_fragment":
            payload = value.get("payload")
            assert isinstance(payload, dict)
            decision = payload.get("decision")
            assert isinstance(decision, str)
            referee_decisions.add(decision)
    return operations, referee_decisions


def test_protocol_22_committed_stable_fixture_runs_full_and_portable_exactly(
    tmp_path: Path,
) -> None:
    """Committed drafts directly cover the fragmented terminal lifecycle."""
    fixture = ATTORNEY_V22_FIXTURE / "stable"
    fixture_before = _run_snapshot(fixture)
    outcomes = []
    for name, runner, portable in (
        ("full", FULL_PUBLIC_RUNNER, False),
        ("portable", PORTABLE_PUBLIC_RUNNER, True),
    ):
        run = tmp_path / f"stable-{name}"
        transcript, tree, result = _committed_v22_fixture_lifecycle(
            fixture,
            run,
            runner=runner,
            portable=portable,
            initial_script="scripted-drafts.json",
        )
        operations, decisions = _accepted_v22_operations(run)
        assert operations["source_review_fragment"] >= 2
        assert operations["source_audit_fragment"] >= 2
        assert operations["source_referee_fragment"] >= 3
        assert operations["ordinary_grade_fragment"] >= 4
        assert operations["contested_grade_fragment"] >= 2
        assert decisions == {"accept_reviewer", "accept_auditor", "unresolved"}
        assert result["terminal_status"] == "COMPLETED"
        outcomes.append((transcript, tree, result))
    assert outcomes[0] == outcomes[1]
    assert _run_snapshot(fixture) == fixture_before


def test_protocol_22_committed_pause_resume_fixture_is_write_free_then_terminal(
    tmp_path: Path,
) -> None:
    """Two invalid committed drafts pause unchanged before a later exact resume."""
    fixture = ATTORNEY_V22_FIXTURE / "pause-resume"
    fixture_before = _run_snapshot(fixture)
    outcomes = []
    for name, runner, portable in (
        ("full", FULL_PUBLIC_RUNNER, False),
        ("portable", PORTABLE_PUBLIC_RUNNER, True),
    ):
        outcomes.append(
            _committed_v22_fixture_lifecycle(
                fixture,
                tmp_path / f"pause-resume-{name}",
                runner=runner,
                portable=portable,
                initial_script="initial-drafts.json",
                resume_script="resume-drafts.json",
            )
        )
        assert outcomes[-1][2]["terminal_status"] == "COMPLETED"
    assert outcomes[0] == outcomes[1]
    assert _run_snapshot(fixture) == fixture_before


def test_protocol_22_scripted_adapter_refuses_wrong_attempt_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = tmp_path / "attempt-probe"
    initialize_evaluation_v22(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    request = next_evaluator_request_v22(probe)
    assert request is not None
    responses = fixture / "responses" / "v22-wrong-attempt.json"
    _write_canonical(
        responses,
        {
            "fixture_type": "local-scripted-drafts-v2.2",
            "responses": [
                {
                    "draft": _v22_draft(request),
                    "expect": {
                        "attempt": 2,
                        "clarification_codes": [],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                }
            ],
        },
    )
    run = tmp_path / "wrong-attempt-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }
    assert not (run / "result.json").exists()


@pytest.mark.parametrize("failure", [RuntimeError, OSError])
def test_protocol_22_provider_crash_resumes_without_repeating_accepted_fragment(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: type[Exception],
) -> None:
    from regulatory_harvest.evaluation import attorney_cli

    fixture = _scripted_fixture_copy(tmp_path)
    responses = _v22_script_for_new_run(
        fixture,
        tmp_path,
        empty_sources=True,
    )
    original = attorney_cli._ScriptedFixtureDraftEvaluatorV22.evaluate_draft
    calls: dict[object, int] = {}

    async def crash_after_first_accepted(
        self: object, prompt: object
    ) -> object:
        calls[self] = calls.get(self, 0) + 1
        if calls[self] == 2:
            raise failure("synthetic provider crash")
        return await original(self, prompt)  # type: ignore[arg-type]

    monkeypatch.setattr(
        attorney_cli._ScriptedFixtureDraftEvaluatorV22,
        "evaluate_draft",
        crash_after_first_accepted,
    )
    run = tmp_path / "crashed-run"
    crashed = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(run),
            "--json",
        ]
    )
    assert crashed == 6
    assert json.loads(capsys.readouterr().out)["pending_call"] == (
        "source-audit-fragment-0001"
    )
    manifest = json.loads((run / "run-manifest.json").read_bytes())
    assert [call["call_id"] for call in manifest["calls"]].count("source-review-0001") == 1

    monkeypatch.setattr(
        attorney_cli._ScriptedFixtureDraftEvaluatorV22,
        "evaluate_draft",
        original,
    )
    continuation_probe = tmp_path / "crash-continuation-probe"
    shutil.copytree(run, continuation_probe)
    continuation = fixture / "responses" / "v22-crash-continuation.json"
    _v22_script_from_run(
        continuation_probe,
        continuation,
        empty_sources=True,
    )
    resumed = main(
        [
            "eval",
            "attorney",
            "resume",
            "--output",
            str(run),
            "--scripted-responses",
            str(continuation),
            "--json",
        ]
    )

    assert resumed == 3
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "INCONCLUSIVE"
    manifest = json.loads((run / "run-manifest.json").read_bytes())
    assert [call["call_id"] for call in manifest["calls"]].count("source-review-0001") == 1


@pytest.mark.parametrize("exhaustion", ["initial", "clarification"])
def test_protocol_22_scripted_exhaustion_is_input_error_before_initialization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    exhaustion: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    probe = tmp_path / f"{exhaustion}-exhaustion-probe"
    initialize_evaluation_v22(
        case,
        probe,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    request = next_evaluator_request_v22(probe)
    assert request is not None
    responses: list[dict[str, object]] = []
    if exhaustion == "clarification":
        responses.append(
            {
                "draft": {"malformed": "private-rejected-draft"},
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": request.request_fingerprint,
                },
                "operation": request.operation.value,
            }
        )
    scripted = fixture / "responses" / f"v22-{exhaustion}-exhaustion.json"
    _write_canonical(
        scripted,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses},
    )
    run = tmp_path / f"{exhaustion}-exhaustion-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(scripted),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }
    assert not run.exists()


@pytest.mark.parametrize(
    "fixture_error", ["initial_exhaustion", "clarification_exhaustion", "malformed", "extra"]
)
def test_protocol_22_attorney_resume_scripted_input_errors_are_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixture_error: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    run = tmp_path / f"resume-{fixture_error}"
    initialize_evaluation_v22(
        case,
        run,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    request = next_evaluator_request_v22(run)
    assert request is not None
    first = {
        "draft": {"malformed": "first-private-draft"},
        "expect": {
            "attempt": 1,
            "clarification_codes": [],
            "request_fingerprint": request.request_fingerprint,
        },
        "operation": request.operation.value,
    }
    second = {
        "draft": {"malformed": "second-private-draft"},
        "expect": {
            "attempt": 2,
            "clarification_codes": ["SUBSTANCE_MISSING"],
            "request_fingerprint": request.request_fingerprint,
        },
        "operation": request.operation.value,
    }
    responses: object
    if fixture_error == "initial_exhaustion":
        responses = []
    elif fixture_error == "clarification_exhaustion":
        responses = [first]
    elif fixture_error == "malformed":
        responses = "not-an-array"
    else:
        responses = [
            first,
            second,
            {
                "draft": {"proposals": [], "review_complete": True},
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": "f" * 64,
                },
                "operation": "source_review_fragment",
            },
        ]
    scripted = fixture / "responses" / f"resume-{fixture_error}.json"
    _write_canonical(
        scripted,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": responses},
    )
    before = _run_snapshot(run)

    status = main(
        [
            "eval",
            "attorney",
            "resume",
            "--output",
            str(run),
            "--scripted-responses",
            str(scripted),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }
    assert _run_snapshot(run) == before


@pytest.mark.parametrize("probe_failure", ["construct", "copy", "read"])
def test_protocol_22_attorney_resume_probe_oserror_is_input_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    probe_failure: str,
) -> None:
    from regulatory_harvest.evaluation import attorney_cli

    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    run = tmp_path / f"probe-{probe_failure}"
    initialize_evaluation_v22(
        case,
        run,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    scripted = _v22_script_for_new_run(fixture, tmp_path, empty_sources=True)
    if probe_failure == "construct":
        def fail_temporary_directory(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError("synthetic probe construction failure")

        monkeypatch.setattr(
            attorney_cli.tempfile, "TemporaryDirectory", fail_temporary_directory
        )
    elif probe_failure == "copy":
        def fail_copy(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise OSError("synthetic probe copy failure")

        monkeypatch.setattr(attorney_cli.shutil, "copytree", fail_copy)
    else:
        async def fail_probe_read(*args: object, **kwargs: object) -> object:
            del args, kwargs
            try:
                raise OSError("synthetic probe read failure")
            except OSError as error:
                raise attorney_artifacts.EvaluationIntegrityError(
                    "evaluation storage read failed"
                ) from error

        monkeypatch.setattr(attorney_cli, "continue_evaluation_v22", fail_probe_read)
    before = _run_snapshot(run)

    status = main(
        [
            "eval",
            "attorney",
            "resume",
            "--output",
            str(run),
            "--scripted-responses",
            str(scripted),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }
    assert _run_snapshot(run) == before


def test_protocol_22_attorney_resume_corrupt_stored_run_is_integrity_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    run = tmp_path / "corrupt-stored-resume"
    initialize_evaluation_v22(
        case,
        run,
        seed_hex="0" * 64,
        generation_capsule_paths=capsule_paths,
    )
    pending = next((run / "requests").glob("*.json"))
    pending.write_bytes(pending.read_bytes() + b"\n")
    scripted = _v22_script_for_new_run(fixture, tmp_path, empty_sources=True)
    before = _run_snapshot(run)

    status = main(
        [
            "eval",
            "attorney",
            "resume",
            "--output",
            str(run),
            "--scripted-responses",
            str(scripted),
            "--json",
        ]
    )

    assert status == 5
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_integrity_invalid",
        "ok": False,
    }
    assert _run_snapshot(run) == before


@pytest.mark.parametrize("fixture_error", ["malformed", "extra"])
def test_protocol_22_scripted_fixture_errors_are_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixture_error: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    scripted = _v22_script_for_new_run(fixture, tmp_path, empty_sources=True)
    payload = json.loads(scripted.read_bytes())
    if fixture_error == "malformed":
        payload["responses"] = "not-an-array"
    else:
        payload["responses"].append(
            {
                "draft": {"proposals": [], "review_complete": True},
                "expect": {
                    "attempt": 1,
                    "clarification_codes": [],
                    "request_fingerprint": "f" * 64,
                },
                "operation": "source_review_fragment",
            }
        )
    _write_canonical(scripted, payload)
    run = tmp_path / f"{fixture_error}-fixture-run"

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(scripted),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "attorney_input_invalid",
        "ok": False,
    }
    assert not run.exists()


@pytest.mark.parametrize("fixture_error", ["missing", "symlink", "oversize"])
def test_protocol_22_scripted_fixture_secure_read_contract(
    tmp_path: Path, fixture_error: str
) -> None:
    scripted = tmp_path / "scripted.json"
    if fixture_error == "symlink":
        target = tmp_path / "target.json"
        _write_canonical(
            target,
            {"fixture_type": "local-scripted-drafts-v2.2", "responses": []},
        )
        scripted.symlink_to(target)
    elif fixture_error == "oversize":
        scripted.write_bytes(b"x" * (16 * 1024 * 1024 + 1))

    with pytest.raises(ValueError, match=r"^scripted draft fixture is unavailable$"):
        _scripted_drafts_from_fixture(scripted)


@pytest.mark.parametrize("protocol", ["1.3", "2.0", "2.1"])
def test_protocol_22_attorney_run_refuses_existing_retained_root_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    protocol: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    run = tmp_path / f"retained-{protocol.replace('.', '')}"
    if protocol == "1.3":
        initialize_evaluation(
            case,
            run,
            seed_hex="7" * 64,
            generation_capsule_paths=capsule_paths,
        )
    elif protocol == "2.0":
        initialize_evaluation_v2(
            case,
            run,
            seed_hex="6" * 64,
            generation_capsule_paths=capsule_paths,
        )
    else:
        initialize_evaluation_v21(
            case,
            run,
            seed_hex="5" * 64,
            generation_capsule_paths=capsule_paths,
        )
    before = _run_snapshot(run)
    scripted = fixture / "responses" / "empty-v22.json"
    _write_canonical(
        scripted,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": []},
    )

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(scripted),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 2
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_retained_read_only",
        "ok": False,
    }
    assert _run_snapshot(run) == before


@pytest.mark.parametrize(
    ("protocol", "corruption"),
    [("1.3", "missing"), ("2.0", "tampered"), ("2.1", "mixed_inventory")],
)
def test_protocol_22_attorney_run_rejects_corrupt_retained_root_integrity_write_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    protocol: str,
    corruption: str,
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    case, capsule_paths = _case_and_capsules_from_fixture(
        fixture / "case.json", root=fixture
    )
    run = tmp_path / f"corrupt-retained-{protocol.replace('.', '')}"
    if protocol == "1.3":
        initialize_evaluation(
            case, run, seed_hex="7" * 64, generation_capsule_paths=capsule_paths
        )
    elif protocol == "2.0":
        initialize_evaluation_v2(
            case, run, seed_hex="6" * 64, generation_capsule_paths=capsule_paths
        )
    else:
        initialize_evaluation_v21(
            case, run, seed_hex="5" * 64, generation_capsule_paths=capsule_paths
        )
    artifact = next(
        path for path in sorted(run.rglob("*"))
        if path.is_file() and path.name != "run-manifest.json"
    )
    if corruption == "missing":
        artifact.unlink()
    elif corruption == "tampered":
        artifact.write_bytes(artifact.read_bytes() + b"\n")
    else:
        (run / "v22-mixed-inventory.json").write_bytes(canonical_json_bytes({}))
    before = _run_snapshot(run)
    scripted = fixture / "responses" / "empty-corrupt-v22.json"
    _write_canonical(
        scripted,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": []},
    )

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(scripted),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 5
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_integrity_invalid",
        "ok": False,
    }
    assert _run_snapshot(run) == before


def test_protocol_22_attorney_run_initializes_existing_empty_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = _v22_script_for_new_run(fixture, tmp_path)
    run = tmp_path / "empty-existing-root"
    run.mkdir()

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(responses),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "COMPLETED"
    assert json.loads((run / "run-manifest.json").read_bytes())["protocol_version"] == "2.2"


@pytest.mark.parametrize(
    "manifest",
    [
        {"protocol_version": "9.9"},
        {"protocol_version": "2.2"},
        {
            "protocol_version": "2.1",
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
        },
    ],
)
def test_protocol_22_attorney_run_existing_unknown_or_tampered_root_is_integrity_invalid(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    manifest: dict[str, object],
) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    run = tmp_path / "invalid-existing-root"
    run.mkdir()
    _write_canonical(run / "run-manifest.json", manifest)
    before = _run_snapshot(run)
    scripted = fixture / "responses" / "empty-v22.json"
    _write_canonical(
        scripted,
        {"fixture_type": "local-scripted-drafts-v2.2", "responses": []},
    )

    status = main(
        [
            "eval",
            "attorney",
            "run",
            "--protocol",
            "2.2",
            "--case",
            str(fixture / "case.json"),
            "--scripted-responses",
            str(scripted),
            "--output",
            str(run),
            "--json",
        ]
    )

    assert status == 5
    assert json.loads(capsys.readouterr().out) == {
        "error": "evaluation_integrity_invalid",
        "ok": False,
    }
    assert _run_snapshot(run) == before
