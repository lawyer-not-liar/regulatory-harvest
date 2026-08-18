import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import regulatory_harvest.evaluation.attorney_artifacts as attorney_artifacts
from regulatory_harvest.cli import main
from regulatory_harvest.storage import canonical_json_bytes

FIXTURE = Path(__file__).parents[1] / "fixtures" / "legalbench-mini"
ATTORNEY_FIXTURE = Path(__file__).parents[1] / "fixtures" / "attorney-eval"


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
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "completed"
    assert (
        json.loads((output / "evaluation-result.json").read_text())["reports"][0][
            "absolute_disposition"
        ]
        == "PASS"
    )


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


def _scripted_fixture_copy(tmp_path: Path) -> Path:
    fixture = tmp_path / "attorney-eval"
    shutil.copytree(ATTORNEY_FIXTURE, fixture)
    return fixture


def _write_canonical(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


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


def test_attorney_cli_case_invalid_is_exit_three(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = fixture / "responses" / "scripted-responses.json"
    data = json.loads(responses.read_text(encoding="utf-8"))
    data["responses"] = data["responses"][:1]
    data["responses"][0]["payload"]["checks"][1]["satisfied"] = False
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

    assert status == 3
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "case-invalid"


def test_attorney_cli_failed_required_candidate_is_exit_four(tmp_path: Path, capsys) -> None:
    fixture = _scripted_fixture_copy(tmp_path)
    responses = fixture / "responses" / "scripted-responses.json"
    data = json.loads(responses.read_text(encoding="utf-8"))
    for response in data["responses"][-2:]:
        response["payload"]["entry_grades"][0].update(
            disposition="MISSING",
            report_location=None,
            report_passage=None,
            finding_codes=["CRITICAL_LEDGER_ENTRY_MISSING"],
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
    assert "CRITICAL_LEDGER_ENTRY_MISSING" in payload["all_issue_codes"]


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
    assert verification["terminal_state"] == "completed"
    assert verification["reports"] == [
        {
            "absolute_disposition": "PASS",
            "all_issue_codes": [],
            "blocking_codes": [],
            "issue_codes": [],
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
