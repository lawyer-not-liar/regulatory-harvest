import json
import subprocess
import sys
from datetime import date
from pathlib import Path

from regulatory_harvest.models import ResearchRequest, SourceInput


def _run(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "regulatory_harvest.cli", *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_request(project: Path) -> Path:
    project.mkdir()
    (project / "rule.txt").write_text(
        "A controller must document material risks.", encoding="utf-8"
    )
    request = ResearchRequest(
        request_id="demo",
        question="What must be documented?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="rule.txt", jurisdiction="US")],
    )
    path = project / "request.json"
    path.write_text(request.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_init_writes_request_only_to_selected_directory(tmp_path: Path) -> None:
    """An implicit output location could overwrite unrelated personal files."""
    project = tmp_path / "project"

    result = _run("init", str(project), "--json")

    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "created": str(project / "request.json"),
        "ok": True,
    }
    assert sorted(path.name for path in project.iterdir()) == ["request.json"]


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    """Overwriting a curated request silently would destroy user work."""
    project = tmp_path / "project"
    first = _run("init", str(project))
    request_path = project / "request.json"
    request_path.write_text("preserve me", encoding="utf-8")

    second = _run("init", str(project), "--json")

    assert first.returncode == 0
    assert second.returncode == 2
    assert request_path.read_text(encoding="utf-8") == "preserve me"


def test_run_validate_and_report_offline_with_json_contract(tmp_path: Path) -> None:
    """A local-only project must work without a server, database, network, or key."""
    request_path = _write_request(tmp_path / "project")
    output = tmp_path / "runs"

    run = _run(
        "run",
        "--request",
        str(request_path),
        "--output",
        str(output),
        "--json",
    )
    bundle_path = output / "demo" / "bundle.json"
    validate = _run("validate", str(bundle_path), "--json")
    report = _run("report", str(bundle_path), "--json")

    assert run.returncode == 0
    assert json.loads(run.stdout) == {
        "bundle": str(bundle_path),
        "ok": True,
        "run_id": "demo",
        "validation_valid": True,
    }
    assert validate.returncode == 0
    assert json.loads(validate.stdout)["valid"] is True
    assert report.returncode == 0
    assert "Attorney review required" in json.loads(report.stdout)["report"]


def test_validate_returns_four_for_invalid_bundle(tmp_path: Path) -> None:
    """Returning success for broken provenance would make automation trust it."""
    request_path = _write_request(tmp_path / "project")
    output = tmp_path / "runs"
    run = _run("run", "--request", str(request_path), "--output", str(output))
    bundle_path = output / "demo" / "bundle.json"
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    payload["request"]["jurisdictions"].append("CA")
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")

    validate = _run("validate", str(bundle_path), "--json")

    assert run.returncode == 0
    assert validate.returncode == 4
    assert json.loads(validate.stdout)["valid"] is False
    assert any(
        issue["code"] == "JURISDICTION_UNCOVERED"
        for issue in json.loads(validate.stdout)["issues"]
    )


def test_report_revalidates_tampered_bundle_and_returns_four(tmp_path: Path) -> None:
    """A report must not repeat a stale valid result after the bundle changes."""
    request_path = _write_request(tmp_path / "project")
    output = tmp_path / "runs"
    run = _run("run", "--request", str(request_path), "--output", str(output))
    bundle_path = output / "demo" / "bundle.json"
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    payload["request"]["question"] = "A tampered question"
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")

    rendered = _run("report", str(bundle_path), "--json")
    response = json.loads(rendered.stdout)

    assert run.returncode == 0
    assert rendered.returncode == 4
    assert response["ok"] is False
    assert "**Validation status:** invalid" in response["report"]
    assert "BUNDLE_HASH_MISMATCH" in response["report"]
