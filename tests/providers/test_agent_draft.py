from regulatory_harvest.analysis import AnalysisDraft, DraftIssue
from regulatory_harvest.providers import (
    AgentDraftModelProvider,
    ModelRequest,
)


def _request(operation: str) -> ModelRequest:
    return ModelRequest(
        operation=operation,
        instructions_version=f"{operation}-v1",
        system_instructions="Use the supplied strict draft.",
        json_schema={},
        source_excerpts=[],
    )


async def test_agent_draft_provider_returns_strict_host_analysis_with_stable_provenance() -> None:
    """Replacing the host draft or operation without changing provenance must be detectable."""
    draft = AnalysisDraft(
        issues=[DraftIssue(issue_id="issue-1", title="Documentation")]
    )
    provider = AgentDraftModelProvider(
        draft,
        host_name="codex",
        model_name="configured-host-model",
    )

    first = await provider.complete(_request("map"))
    repeated = await provider.complete(_request("map"))
    build = await provider.complete(_request("build"))

    assert first.parsed == draft
    assert first.provider_name == "codex"
    assert first.model_name == "configured-host-model"
    assert first.prompt_fingerprint == repeated.prompt_fingerprint
    assert first.prompt_fingerprint != build.prompt_fingerprint
    assert len(first.prompt_fingerprint) == 64

