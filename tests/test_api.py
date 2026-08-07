import json
from datetime import date
from pathlib import Path

import pytest

from regulatory_harvest.api import run_research, run_research_sync
from regulatory_harvest.models import ResearchRequest, SourceInput


def _write_project(project: Path) -> Path:
    project.mkdir()
    (project / "rule.txt").write_text(
        "A controller must retain records.", encoding="utf-8"
    )
    request = ResearchRequest(
        request_id="demo",
        question="What records are required?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[
            SourceInput(location="rule.txt", title="Example Rule", jurisdiction="US")
        ],
    )
    request_path = project / "request.json"
    request_path.write_text(request.model_dump_json(indent=2), encoding="utf-8")
    return request_path


@pytest.mark.asyncio
async def test_api_runs_request_relative_source_without_changing_cwd(tmp_path: Path) -> None:
    """Resolving relative inputs against cwd would break portable project folders."""
    request_path = _write_project(tmp_path / "project")
    output = tmp_path / "selected-output"

    result = await run_research(request_path, output)

    assert result.bundle.sources[0].origin == "rule.txt"
    assert result.bundle.sources[0].normalized_text == "A controller must retain records."
    assert (output / "demo" / "bundle.json").exists()
    assert not (tmp_path / "bundle.json").exists()


@pytest.mark.asyncio
async def test_sync_api_refuses_to_nest_an_active_event_loop(tmp_path: Path) -> None:
    """Calling asyncio.run inside an active loop would crash unpredictably."""
    request_path = _write_project(tmp_path / "project")
    with pytest.raises(RuntimeError, match="active event loop"):
        run_research_sync(request_path, tmp_path / "runs")


def test_sync_api_returns_models_outside_event_loop(tmp_path: Path) -> None:
    """Returning dictionaries would weaken the documented Python contract."""
    request_path = _write_project(tmp_path / "project")
    result = run_research_sync(request_path, tmp_path / "runs")
    assert result.bundle.request.request_id == "demo"
    json.loads((tmp_path / "runs" / "demo" / "bundle.json").read_text())
