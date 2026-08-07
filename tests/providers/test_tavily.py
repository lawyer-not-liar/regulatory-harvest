from datetime import date

import httpx
import pytest
import respx

from regulatory_harvest.providers import SearchQuery
from regulatory_harvest.providers.errors import ProviderError
from regulatory_harvest.providers.tavily import TavilySearchProvider


@pytest.mark.asyncio
@respx.mock
async def test_tavily_adapter_sends_bounded_search_and_maps_results() -> None:
    """Requesting generated answers or raw pages would expand cost and data exposure."""
    route = respx.post("https://api.tavily.com/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "query": "privacy rule",
                "results": [
                    {
                        "title": "Agency Rule",
                        "url": "https://agency.example/rule",
                        "content": "The rule applies to controllers.",
                        "score": 0.91,
                        "published_date": "2026-07-01",
                    }
                ],
                "response_time": "0.5",
            },
        )
    )
    provider = TavilySearchProvider(api_key="tvly-secret")

    results = await provider.search(
        SearchQuery(
            query="privacy rule",
            jurisdictions=["US", "CA"],
            as_of=date(2026, 8, 5),
            limit=3,
        )
    )

    assert len(results) == 1
    assert results[0].url == "https://agency.example/rule"
    assert results[0].snippet == "The rule applies to controllers."
    assert results[0].rank == 1
    assert results[0].published_date == date(2026, 7, 1)
    request = route.calls[0].request
    payload = request.content.decode()
    assert "Jurisdictions: US, CA" in payload
    assert "As of: 2026-08-05" in payload
    assert '"search_depth":"basic"' in payload
    assert '"max_results":3' in payload
    assert '"include_answer":false' in payload
    assert '"include_raw_content":false' in payload
    assert "tvly-secret" not in str(results)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "retryable"), [(400, False), (429, True), (500, True)])
async def test_tavily_adapter_classifies_http_errors_safely(
    status: int,
    retryable: bool,
) -> None:
    """Automation needs retry semantics without receiving secret-bearing bodies."""
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            status,
            text="must-not-leak-tvly-secret",
            request=request,
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        provider = TavilySearchProvider(api_key="tvly-secret", client=client)
        with pytest.raises(ProviderError) as captured:
            await provider.search(
                SearchQuery(
                    query="privacy rule",
                    jurisdictions=["US"],
                    as_of=date(2026, 8, 5),
                )
            )
    assert captured.value.retryable is retryable
    assert captured.value.status_code == status
    assert "must-not-leak" not in str(captured.value)
