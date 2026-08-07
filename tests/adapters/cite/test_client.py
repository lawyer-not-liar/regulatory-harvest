import json
from pathlib import Path

import httpx
import pytest

from regulatory_harvest.adapters.cite import (
    CiteClient,
    CiteCompatibilityError,
    CiteRequestError,
)

FIXTURE = Path(__file__).parent / "fixtures" / "capabilities.json"


@pytest.mark.asyncio
async def test_discovery_detects_and_caches_supported_operations() -> None:
    """Dropping or repeatedly probing a discovered operation would make runs unreliable."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                json={
                    "mcpServers": {
                        "cite": {
                            "url": "https://cite.example/mcp/",
                            "transport": "streamable-http",
                            "authentication": None,
                        }
                    }
                },
            )
        if request.url.path == "/mcp/":
            return httpx.Response(200, json=fixture["mcp"])
        if request.url.path == "/llms.txt":
            return httpx.Response(
                200,
                text="- `list_documents`\n- `get_document_text`\n- `list_annotations`",
            )
        if request.url.path == "/graphql":
            return httpx.Response(200, json=fixture["graphql"])
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = CiteClient(
        "https://cite.example",
        transport=httpx.MockTransport(handler),
    )
    first = await client.discover_capabilities()
    second = await client.discover_capabilities()

    assert first is second
    assert first.can_read_documents is True
    assert first.can_read_annotations is True
    assert first.can_read_relationships is True
    assert first.can_write_annotations is True
    assert first.can_write_relationships is True
    assert first.mcp_url == "https://cite.example/mcp/"
    assert calls == [
        ("GET", "/.well-known/mcp.json"),
        ("POST", "/mcp/"),
        ("GET", "/llms.txt"),
        ("POST", "/graphql"),
    ]
    await client.aclose()


def test_client_repr_redacts_token() -> None:
    """A diagnostic representation must not leak the configured bearer token."""
    client = CiteClient("https://cite.example", token="secret-value")

    rendered = repr(client)

    assert "secret-value" not in rendered
    assert "token=<redacted>" in rendered


def test_client_rejects_base_url_with_embedded_credentials() -> None:
    """Accepting URL credentials would leak them through routine status output."""
    with pytest.raises(ValueError, match="credentials"):
        CiteClient("https://user:password@cite.example")


def _mcp_text_result(payload: object, *, request_id: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payload),
                }
            ]
        },
    }


@pytest.mark.asyncio
async def test_list_documents_uses_discovered_mcp_and_returns_typed_page() -> None:
    """Calling the wrong MCP operation or corpus would import unrelated evidence."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    observed_call: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                json={
                    "mcpServers": {
                        "cite": {
                            "url": "https://cite.example/mcp/",
                            "transport": "streamable-http",
                        }
                    }
                },
            )
        if request.url.path == "/mcp/":
            body = json.loads(request.content)
            if body["method"] == "tools/list":
                return httpx.Response(200, json=fixture["mcp"])
            observed_call.update(body)
            assert request.headers["Authorization"] == "Bearer adapter-token"
            return httpx.Response(
                200,
                json=_mcp_text_result(
                    {
                        "total_count": 1,
                        "documents": [
                            {
                                "slug": "public-rule",
                                "title": "Public Rule",
                                "description": "A synthetic public fixture",
                                "page_count": 2,
                                "file_type": "application/pdf",
                                "created": "2026-08-01T12:00:00+00:00",
                            }
                        ],
                    },
                    request_id=2,
                ),
            )
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text="# cite")
        if request.url.path == "/graphql":
            return httpx.Response(200, json=fixture["graphql"])
        raise AssertionError(f"unexpected request: {request.url}")

    client = CiteClient(
        "https://cite.example",
        token="adapter-token",
        transport=httpx.MockTransport(handler),
    )

    page = await client.list_documents("public-corpus", limit=25, offset=50)

    assert page.total_count == 1
    assert page.documents[0].slug == "public-rule"
    assert page.documents[0].page_count == 2
    assert observed_call["params"] == {
        "name": "list_documents",
        "arguments": {"corpus_slug": "public-corpus", "limit": 25, "offset": 50},
    }
    await client.aclose()


@pytest.mark.asyncio
async def test_get_document_reassembles_bounded_text_pages() -> None:
    """Ignoring next_offset would silently truncate long legal authorities."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    offsets: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                json={
                    "mcpServers": {
                        "cite": {"url": "https://cite.example/mcp/"}
                    }
                },
            )
        if request.url.path == "/mcp/":
            body = json.loads(request.content)
            if body["method"] == "tools/list":
                return httpx.Response(200, json=fixture["mcp"])
            arguments = body["params"]["arguments"]
            offset = arguments["char_offset"]
            offsets.append(offset)
            payload = (
                {
                    "document_slug": "public-rule",
                    "page_count": 1,
                    "total_chars": 11,
                    "char_offset": 0,
                    "text": "hello ",
                    "next_offset": 6,
                    "truncated": True,
                }
                if offset == 0
                else {
                    "document_slug": "public-rule",
                    "page_count": 1,
                    "total_chars": 11,
                    "char_offset": 6,
                    "text": "world",
                    "next_offset": None,
                    "truncated": False,
                }
            )
            return httpx.Response(
                200,
                json=_mcp_text_result(payload, request_id=2 + len(offsets)),
            )
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text="# cite")
        if request.url.path == "/graphql":
            return httpx.Response(200, json=fixture["graphql"])
        raise AssertionError(f"unexpected request: {request.url}")

    client = CiteClient(
        "https://cite.example",
        transport=httpx.MockTransport(handler),
    )

    document = await client.get_document("public-corpus", "public-rule", chunk_chars=6)

    assert document.text == "hello world"
    assert document.total_chars == 11
    assert offsets == [0, 6]
    await client.aclose()


@pytest.mark.asyncio
async def test_missing_annotation_capability_fails_before_tool_call() -> None:
    """A missing read surface must be explicit rather than producing an empty import."""
    tool_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal tool_calls
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                json={
                    "mcpServers": {
                        "cite": {"url": "https://cite.example/mcp/"}
                    }
                },
            )
        if request.url.path == "/mcp/":
            body = json.loads(request.content)
            if body["method"] == "tools/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"tools": []},
                    },
                )
            tool_calls += 1
            return httpx.Response(500)
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text="# cite")
        if request.url.path == "/graphql":
            return httpx.Response(200, json={"data": {"__schema": {"mutationType": None}}})
        raise AssertionError(f"unexpected request: {request.url}")

    client = CiteClient(
        "https://cite.example",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(CiteCompatibilityError, match="list_annotations"):
        await client.list_annotations("public-corpus", "public-rule")

    assert tool_calls == 0
    await client.aclose()


@pytest.mark.asyncio
async def test_request_failure_does_not_expose_token_or_remote_body() -> None:
    """A hostile remote error must not escape through adapter diagnostics."""
    secret = "top-secret-token"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text=f"private document text and {secret}")

    client = CiteClient(
        "https://cite.example",
        token=secret,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(CiteRequestError) as raised:
        await client._json_request("GET", "https://cite.example/private")

    assert secret not in str(raised.value)
    assert "private document text" not in str(raised.value)
    await client.aclose()


@pytest.mark.asyncio
async def test_create_annotation_uses_documented_graphql_mutation() -> None:
    """Wrong mutation variables could attach evidence to the wrong document or page."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    observed_variables: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(404)
        if request.url.path == "/llms.txt":
            return httpx.Response(404)
        if request.url.path == "/graphql":
            body = json.loads(request.content)
            if "__schema" in body["query"]:
                return httpx.Response(200, json=fixture["graphql"])
            observed_variables.update(body["variables"])
            assert request.headers["Authorization"] == "Bearer write-token"
            return httpx.Response(
                200,
                json={
                    "data": {
                        "addAnnotation": {
                            "ok": True,
                            "annotation": {"id": "annotation-42"},
                        }
                    }
                },
            )
        raise AssertionError(f"unexpected request: {request.url}")

    client = CiteClient(
        "https://cite.example",
        token="write-token",
        transport=httpx.MockTransport(handler),
    )

    receipt = await client.create_annotation(
        corpus_id="corpus-node-id",
        document_id="document-node-id",
        annotation_label_id="label-node-id",
        raw_text="A controller must document risks.",
        page=0,
        annotation_json={"harvest": {"citation_id": "citation-1"}},
        long_description="Regulatory Harvest provenance: citation-1",
    )

    assert receipt.remote_id == "annotation-42"
    assert receipt.operation == "addAnnotation"
    assert observed_variables == {
        "annotationLabelId": "label-node-id",
        "annotationType": "TOKEN_LABEL",
        "corpusId": "corpus-node-id",
        "documentId": "document-node-id",
        "json": {"harvest": {"citation_id": "citation-1"}},
        "longDescription": "Regulatory Harvest provenance: citation-1",
        "page": 0,
        "rawText": "A controller must document risks.",
    }
    await client.aclose()


@pytest.mark.asyncio
async def test_create_relationship_uses_annotation_relationship_mutation() -> None:
    """Using document relationships would misrepresent claim-to-citation edges."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    observed_variables: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(404)
        if request.url.path == "/llms.txt":
            return httpx.Response(404)
        if request.url.path == "/graphql":
            body = json.loads(request.content)
            if "__schema" in body["query"]:
                return httpx.Response(200, json=fixture["graphql"])
            observed_variables.update(body["variables"])
            return httpx.Response(
                200,
                json={
                    "data": {
                        "addRelationship": {
                            "ok": True,
                            "relationship": {"id": "relationship-9"},
                            "message": None,
                        }
                    }
                },
            )
        raise AssertionError(f"unexpected request: {request.url}")

    client = CiteClient(
        "https://cite.example",
        token="write-token",
        transport=httpx.MockTransport(handler),
    )

    receipt = await client.create_relationship(
        corpus_id="corpus-node-id",
        document_id="document-node-id",
        relationship_label_id="supports-label-id",
        source_ids=["finding-annotation-id"],
        target_ids=["citation-annotation-id"],
    )

    assert receipt.remote_id == "relationship-9"
    assert observed_variables == {
        "corpusId": "corpus-node-id",
        "documentId": "document-node-id",
        "relationshipLabelId": "supports-label-id",
        "sourceIds": ["finding-annotation-id"],
        "targetIds": ["citation-annotation-id"],
    }
    await client.aclose()


@pytest.mark.asyncio
async def test_response_limit_rejects_oversized_discovery_body() -> None:
    """An unbounded discovery response could exhaust a local research process."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 65)

    client = CiteClient(
        "https://cite.example",
        max_response_bytes=64,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(CiteRequestError, match="response size limit"):
        await client._text_request("https://cite.example/llms.txt")

    await client.aclose()


@pytest.mark.asyncio
async def test_discovery_refuses_cross_origin_mcp_endpoint() -> None:
    """A discovery document must not redirect configured bearer credentials to another host."""
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                json={
                    "mcpServers": {"cite": {"url": "https://attacker.example/mcp/"}}
                },
            )
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text="- `list_documents`\n- `get_document_text`")
        if request.url.path == "/graphql":
            return httpx.Response(200, json={"data": {"__schema": {"mutationType": None}}})
        raise AssertionError(f"cross-origin request was attempted: {request.url}")

    client = CiteClient(
        "https://cite.example",
        token="must-stay-local",
        transport=httpx.MockTransport(handler),
    )

    capabilities = await client.discover_capabilities()

    assert capabilities.mcp_url is None
    assert capabilities.can_read_documents is False
    assert requested_hosts == ["cite.example", "cite.example", "cite.example"]
    await client.aclose()
