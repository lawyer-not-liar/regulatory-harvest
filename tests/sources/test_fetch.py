from pathlib import Path

import httpx
import pytest
import respx

from regulatory_harvest.models import FetchStatus, SourceInput, SourceQuality
from regulatory_harvest.sources import DefaultSourceFetcher

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.mark.asyncio
async def test_fetch_local_text_records_normalized_provenance() -> None:
    """Dropping local origin or content identity would make the bundle unauditable."""
    source_input = SourceInput(
        location=str(FIXTURES / "public-rule.txt"),
        title="Example Public Rule",
        jurisdiction="US",
        source_quality=SourceQuality.PRIMARY,
        license_assertion="Apache-2.0",
    )
    record = await DefaultSourceFetcher().fetch(source_input)

    assert record.fetch_status is FetchStatus.SUCCEEDED
    assert record.display_name == "Example Public Rule"
    assert record.jurisdiction == "US"
    assert record.source_quality is SourceQuality.PRIMARY
    assert record.content_hash is not None and len(record.content_hash) == 64
    assert record.normalized_text.endswith("before deployment.")


@pytest.mark.asyncio
async def test_fetch_relative_local_file_from_explicit_base_directory(
    tmp_path: Path,
) -> None:
    """Resolving against process cwd would make portable request files fail."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "rule.txt").write_text("A controller must retain records.", encoding="utf-8")

    record = await DefaultSourceFetcher(base_dir=project).fetch(
        SourceInput(location="rule.txt", title="Portable Rule")
    )

    assert record.fetch_status is FetchStatus.SUCCEEDED
    assert record.origin == "rule.txt"
    assert record.normalized_text == "A controller must retain records."


@pytest.mark.asyncio
async def test_fetch_unsupported_local_file_returns_failed_record(tmp_path: Path) -> None:
    """Raising past the source boundary would silently lose the failed source attempt."""
    binary = tmp_path / "rule.bin"
    binary.write_bytes(b"\x00\x01")

    record = await DefaultSourceFetcher().fetch(SourceInput(location=str(binary)))

    assert record.fetch_status is FetchStatus.FAILED
    assert record.source_quality is SourceQuality.UNUSABLE
    assert record.error is not None
    assert record.content_hash is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_url_revalidates_private_redirect() -> None:
    """Following redirects without validation would bypass the public-address gate."""
    public_url = "https://93.184.216.34/start"
    respx.get(public_url).mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
    )

    record = await DefaultSourceFetcher().fetch(SourceInput(location=public_url))

    assert record.fetch_status is FetchStatus.FAILED
    assert record.error is not None
    assert record.error.category == "unsafe_source"
    assert respx.calls.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_fetch_url_enforces_body_limit() -> None:
    """Reading an unbounded response would expose the process to memory exhaustion."""
    public_url = "https://93.184.216.34/large"
    respx.get(public_url).mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"x" * 11,
        )
    )

    record = await DefaultSourceFetcher(max_bytes=10).fetch(SourceInput(location=public_url))

    assert record.fetch_status is FetchStatus.FAILED
    assert record.error is not None
    assert record.error.category == "source_too_large"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_url_normalizes_successful_html() -> None:
    """Returning raw HTML would make citations depend on executable markup."""
    public_url = "https://93.184.216.34/rule"
    respx.get(public_url).mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"<h1>Rule</h1><p>A controller must act.</p>",
        )
    )

    record = await DefaultSourceFetcher().fetch(SourceInput(location=public_url))

    assert record.fetch_status is FetchStatus.SUCCEEDED
    assert record.media_type == "text/html"
    assert record.normalized_text == "Rule\nA controller must act."
