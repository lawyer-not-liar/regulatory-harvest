from datetime import date

import pytest
from pydantic import ValidationError

from regulatory_harvest.models import SourceInput, SourceRecord
from regulatory_harvest.providers import (
    AnalysisDraft,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    SearchProvider,
    SearchQuery,
    SearchResult,
    SourceFetcher,
)


class FakeModelProvider:
    async def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            parsed=AnalysisDraft(),
            provider_name="fake",
            model_name="fake-model",
            prompt_fingerprint="a" * 64,
        )


class FakeSearchProvider:
    async def search(self, query: SearchQuery) -> list[SearchResult]:
        return []


class FakeSourceFetcher:
    async def fetch(self, source_input: SourceInput) -> SourceRecord:
        raise NotImplementedError


def test_provider_protocols_accept_structural_implementations() -> None:
    """Adding inheritance coupling would prevent user-defined adapters."""
    assert isinstance(FakeModelProvider(), ModelProvider)
    assert isinstance(FakeSearchProvider(), SearchProvider)
    assert isinstance(FakeSourceFetcher(), SourceFetcher)


def test_model_request_rejects_credentials_as_unknown_fields() -> None:
    """Permitting arbitrary provider config would serialize secrets into run artifacts."""
    with pytest.raises(ValidationError):
        ModelRequest.model_validate(
            {
                "operation": "build",
                "instructions_version": "build-v1",
                "system_instructions": "Return structured findings.",
                "json_schema": {},
                "source_excerpts": [],
                "api_key": "must-not-serialize",
            }
        )


def test_search_query_requires_positive_result_limit() -> None:
    """Removing the bound would permit an unbounded search request."""
    with pytest.raises(ValidationError):
        SearchQuery(query="privacy rules", jurisdictions=["US"], as_of=date.today(), limit=0)
