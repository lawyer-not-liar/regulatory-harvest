"""Optional Tavily Search API adapter."""

from __future__ import annotations

import os
from datetime import date
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from regulatory_harvest.providers.protocols import SearchQuery, SearchResult
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .errors import ProviderError

_ENDPOINT = "https://api.tavily.com/search"


class _TavilyResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str
    url: str
    content: str
    published_date: date | None = None


class _TavilyResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    results: list[_TavilyResult]


class TavilySearchProvider:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
        search_depth: Literal["basic", "advanced", "fast", "ultra-fast"] = "basic",
        timeout_seconds: float = 20.0,
    ) -> None:
        resolved_key = api_key or os.getenv("TAVILY_API_KEY")
        if not resolved_key:
            raise ValueError("TAVILY_API_KEY is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._api_key = resolved_key
        self._client = client
        self.search_depth = search_depth
        self.timeout = httpx.Timeout(timeout_seconds)

    @property
    def configuration_fingerprint(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "adapter": "tavily-search-v1",
                    "endpoint": _ENDPOINT,
                    "search_depth": self.search_depth,
                }
            )
        )

    async def search(self, query: SearchQuery) -> list[SearchResult]:
        contextual_query = (
            f"{query.query}\n"
            f"Jurisdictions: {', '.join(query.jurisdictions)}\n"
            f"As of: {query.as_of.isoformat()}"
        )
        payload = {
            "include_answer": False,
            "include_raw_content": False,
            "max_results": query.limit,
            "query": contextual_query,
            "search_depth": self.search_depth,
        }
        try:
            response = await self._post(payload)
            response.raise_for_status()
            parsed = _TavilyResponse.model_validate(response.json())
        except httpx.HTTPStatusError as error:
            status_code = error.response.status_code
            raise ProviderError(
                "Tavily request failed.",
                provider="tavily",
                retryable=status_code == 429 or status_code >= 500,
                status_code=status_code,
            ) from None
        except httpx.HTTPError:
            raise ProviderError(
                "Tavily request failed.",
                provider="tavily",
                retryable=True,
            ) from None
        except (ValidationError, ValueError):
            raise ProviderError(
                "Tavily returned an invalid response.",
                provider="tavily",
                retryable=False,
            ) from None

        return [
            SearchResult(
                url=result.url,
                title=result.title,
                snippet=result.content,
                rank=index,
                published_date=result.published_date,
            )
            for index, result in enumerate(parsed.results, start=1)
        ]

    async def _post(self, payload: dict[str, object]) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._api_key}"}
        if self._client is not None:
            return await self._client.post(_ENDPOINT, json=payload, headers=headers)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            return await client.post(_ENDPOINT, json=payload, headers=headers)
