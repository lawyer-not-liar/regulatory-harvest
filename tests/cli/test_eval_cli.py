import json
import shutil
import subprocess
import sys
from pathlib import Path

from regulatory_harvest.cli import main

FIXTURE = Path(__file__).parents[1] / "fixtures" / "legalbench-mini"


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
