import os

import pytest

from regulatory_harvest.adapters.cite import CiteClient


@pytest.mark.live
@pytest.mark.asyncio
async def test_configured_live_cite_supports_read_only_document_discovery() -> None:
    """Public cite interface drift must be observable without mutating the remote."""
    base_url = os.environ.get("HARVEST_LIVE_CITE_URL")
    corpus = os.environ.get("HARVEST_LIVE_CITE_CORPUS")
    if not base_url or not corpus:
        pytest.skip("set HARVEST_LIVE_CITE_URL and HARVEST_LIVE_CITE_CORPUS")

    async with CiteClient(
        base_url,
        token=os.environ.get("HARVEST_LIVE_CITE_TOKEN"),
    ) as client:
        capabilities = await client.discover_capabilities()
        assert capabilities.can_read_documents
        documents = await client.list_documents(corpus, limit=1)

    assert documents.total_count >= len(documents.documents)
