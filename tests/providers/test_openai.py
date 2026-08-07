from __future__ import annotations

from dataclasses import dataclass

import pytest

from regulatory_harvest.analysis import AnalysisDraft, DraftIssue
from regulatory_harvest.providers import ModelRequest, SourceExcerpt
from regulatory_harvest.providers.errors import ProviderError
from regulatory_harvest.providers.openai import OpenAIModelProvider


@dataclass
class FakeUsage:
    input_tokens: int = 100
    output_tokens: int = 25
    total_tokens: int = 125


@dataclass
class FakeResponse:
    output_parsed: object
    id: str = "resp_test"
    model: str = "explicit-model"
    usage: FakeUsage | None = None


class FakeResponses:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.request: dict[str, object] | None = None

    async def parse(self, **kwargs: object) -> FakeResponse:
        self.request = kwargs
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeClient:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.responses = FakeResponses(response)


class FakeAPIError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__("must-not-leak-api-key")
        self.status_code = status_code


def _request() -> ModelRequest:
    return ModelRequest(
        operation="map",
        instructions_version="map-v1",
        system_instructions="Identify issues and preserve uncertainty.",
        json_schema=AnalysisDraft.model_json_schema(),
        source_excerpts=[
            SourceExcerpt(
                source_id="src_rule",
                text="A controller must document risks.",
                metadata={"jurisdiction": "US"},
            )
        ],
        safe_metadata={"question": "What must be documented?"},
    )


@pytest.mark.asyncio
async def test_openai_adapter_parses_pydantic_output_and_records_safe_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manual JSON parsing or credential capture would break this boundary."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    parsed = AnalysisDraft(
        issues=[DraftIssue(issue_id="issue-1", title="Documentation")]
    )
    client = FakeClient(FakeResponse(output_parsed=parsed, usage=FakeUsage()))
    provider = OpenAIModelProvider(model="explicit-model", client=client)

    response = await provider.complete(_request())

    assert response.parsed == parsed
    assert response.response_id == "resp_test"
    assert response.model_name == "explicit-model"
    assert response.usage == {
        "input_tokens": 100,
        "output_tokens": 25,
        "total_tokens": 125,
    }
    assert len(response.prompt_fingerprint) == 64
    assert client.responses.request is not None
    assert client.responses.request["text_format"] is AnalysisDraft
    assert client.responses.request["store"] is False
    assert "A controller must document risks." in str(client.responses.request["input"])
    assert "api_key" not in response.model_dump_json()


def test_openai_adapter_requires_key_only_without_explicit_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Requiring ambient credentials for an injected client would prevent safe testing."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    OpenAIModelProvider(
        model="explicit-model",
        client=FakeClient(FakeResponse(output_parsed=AnalysisDraft())),
    )
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAIModelProvider(model="explicit-model")


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "retryable"), [(400, False), (429, True), (503, True)])
async def test_openai_adapter_classifies_errors_without_leaking_provider_message(
    status: int,
    retryable: bool,
) -> None:
    """Leaking upstream exception text could expose headers or credentials."""
    provider = OpenAIModelProvider(
        model="explicit-model",
        client=FakeClient(FakeAPIError(status)),
    )
    with pytest.raises(ProviderError) as captured:
        await provider.complete(_request())
    assert captured.value.retryable is retryable
    assert captured.value.status_code == status
    assert "must-not-leak" not in str(captured.value)
