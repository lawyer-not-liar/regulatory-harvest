"""Protocols and safe request models for optional providers."""

from datetime import date
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field

from regulatory_harvest.analysis.drafts import AnalysisDraft
from regulatory_harvest.models import SourceInput, SourceRecord
from regulatory_harvest.models.base import StrictModel


class SourceExcerpt(StrictModel):
    source_id: str
    text: str
    metadata: dict[str, str] = Field(default_factory=dict)


class ModelRequest(StrictModel):
    operation: Literal["map", "build"]
    instructions_version: str
    system_instructions: str
    json_schema: dict[str, object]
    source_excerpts: list[SourceExcerpt]
    safe_metadata: dict[str, str] = Field(default_factory=dict)


class ModelResponse(StrictModel):
    parsed: AnalysisDraft
    provider_name: str
    model_name: str
    response_id: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)
    prompt_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class SearchQuery(StrictModel):
    query: str
    jurisdictions: list[str] = Field(min_length=1)
    as_of: date
    limit: int = Field(default=10, ge=1, le=100)


class SearchResult(StrictModel):
    url: str
    title: str
    snippet: str
    rank: int = Field(ge=1)
    published_date: date | None = None


@runtime_checkable
class ModelProvider(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse:
        """Produce a strict analysis draft from safe provider input."""
        ...


@runtime_checkable
class SearchProvider(Protocol):
    async def search(self, query: SearchQuery) -> list[SearchResult]:
        """Return provider-neutral search results."""
        ...


@runtime_checkable
class SourceFetcher(Protocol):
    async def fetch(self, source_input: SourceInput) -> SourceRecord:
        """Fetch and normalize one explicit source input."""
        ...
