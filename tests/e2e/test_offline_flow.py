import json
import shutil
import subprocess
import sys
from pathlib import Path

EXAMPLE = Path(__file__).parents[2] / "examples" / "offline"


def _run(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "regulatory_harvest.cli", *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_offline_example_produces_valid_portable_artifacts(tmp_path: Path) -> None:
    """Depending on repo paths, a network, or a key would break first-use success."""
    project = tmp_path / "offline"
    shutil.copytree(EXAMPLE, project)

    run = _run(
        "run",
        "--request",
        "request.json",
        "--output",
        "runs",
        "--json",
        cwd=project,
    )
    bundle = project / "runs" / "offline-example" / "bundle.json"
    report = project / "runs" / "offline-example" / "report.md"
    validate = _run("validate", str(bundle), "--json", cwd=project)

    assert run.returncode == 0, run.stderr
    assert bundle.exists()
    assert report.exists()
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["valid"] is True
    bundle_text = bundle.read_text(encoding="utf-8")
    assert str(tmp_path) not in bundle_text
    assert "OPENAI_API_KEY" not in bundle_text
    assert "TAVILY_API_KEY" not in bundle_text
