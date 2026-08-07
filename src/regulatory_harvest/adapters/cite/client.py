"""Capability-aware client for cite's documented MCP and GraphQL surfaces."""

from __future__ import annotations

import json
import re
from typing import cast
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import ValidationError

from .models import (
    CiteAnnotationPage,
    CiteCapabilities,
    CiteDocumentPage,
    CiteDocumentText,
    CiteGraphQLIntrospection,
    CiteGraphQLMutationResponse,
    CiteMcpCallResponse,
    CiteMcpDiscovery,
    CiteMcpToolListResponse,
    CiteMutationReceipt,
    CiteRelationshipPage,
)

USER_AGENT = "regulatory-harvest/0.1 cite-adapter"
_CAPABILITY_QUERY = """
query HarvestCiteCapabilities {
  __schema { mutationType { fields { name } } }
}
""".strip()
_DOCUMENT_OPERATIONS = {"list_documents", "get_document_text"}
_ADD_ANNOTATION_MUTATION = """
mutation HarvestAddAnnotation(
  $annotationLabelId: String!
  $annotationType: LabelType!
  $corpusId: String!
  $documentId: String!
  $json: GenericScalar!
  $longDescription: String
  $page: Int!
  $rawText: String!
) {
  addAnnotation(
    annotationLabelId: $annotationLabelId
    annotationType: $annotationType
    corpusId: $corpusId
    documentId: $documentId
    json: $json
    longDescription: $longDescription
    page: $page
    rawText: $rawText
  ) { ok annotation { id } }
}
""".strip()
_ADD_RELATIONSHIP_MUTATION = """
mutation HarvestAddRelationship(
  $corpusId: String!
  $documentId: String!
  $relationshipLabelId: String!
  $sourceIds: [String]!
  $targetIds: [String]!
) {
  addRelationship(
    corpusId: $corpusId
    documentId: $documentId
    relationshipLabelId: $relationshipLabelId
    sourceIds: $sourceIds
    targetIds: $targetIds
  ) { ok relationship { id } message }
}
""".strip()


class CiteError(RuntimeError):
    """Base class for safe, user-facing cite adapter failures."""


class CiteRequestError(CiteError):
    """A bounded external request failed or returned an invalid response."""


class CiteCompatibilityError(CiteError):
    """The target cite instance lacks a required documented operation."""


def _normalize_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("cite base URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("cite base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("cite base URL must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class CiteClient:
    """Small asynchronous client with lifetime-scoped capability caching."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout_seconds: float = 10.0,
        max_document_chars: int = 5_000_000,
        max_response_bytes: int = 5_000_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self._token = token
        if max_document_chars < 1:
            raise ValueError("max_document_chars must be positive")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        self._max_document_chars = max_document_chars
        self._max_response_bytes = max_response_bytes
        headers = {"User-Agent": USER_AGENT}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
            follow_redirects=False,
        )
        self._capabilities: CiteCapabilities | None = None
        self._request_id = 1

    def __repr__(self) -> str:
        token = "<redacted>" if self._token is not None else "None"
        return f"CiteClient(base_url={self.base_url!r}, token={token})"

    async def __aenter__(self) -> CiteClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def _json_request(
        self,
        method: str,
        url: str,
        *,
        json_body: object | None = None,
    ) -> object:
        try:
            body = await self._bytes_request(method, url, json_body=json_body)
            return cast(object, json.loads(body))
        except CiteRequestError:
            raise
        except (ValueError, json.JSONDecodeError) as error:
            path = urlsplit(url).path
            raise CiteRequestError(f"cite {method} {path} failed") from error

    async def _text_request(self, url: str) -> str:
        try:
            body = await self._bytes_request("GET", url)
            return body.decode("utf-8")
        except CiteRequestError:
            raise
        except UnicodeDecodeError as error:
            path = urlsplit(url).path
            raise CiteRequestError(f"cite GET {path} failed") from error

    async def _bytes_request(
        self,
        method: str,
        url: str,
        *,
        json_body: object | None = None,
    ) -> bytes:
        request = self._http.build_request(method, url, json=json_body)
        response: httpx.Response | None = None
        try:
            response = await self._http.send(request, stream=True)
            response.raise_for_status()
            declared_size = response.headers.get("Content-Length")
            if declared_size is not None and int(declared_size) > self._max_response_bytes:
                raise CiteRequestError("cite response size limit exceeded")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > self._max_response_bytes:
                    raise CiteRequestError("cite response size limit exceeded")
                chunks.append(chunk)
            return b"".join(chunks)
        except CiteRequestError:
            raise
        except (httpx.HTTPError, ValueError) as error:
            path = urlsplit(url).path
            raise CiteRequestError(f"cite {method} {path} failed") from error
        finally:
            if response is not None:
                await response.aclose()

    def _is_same_origin(self, candidate: str) -> bool:
        base = urlsplit(self.base_url)
        target = urlsplit(candidate)
        return (
            target.scheme == base.scheme
            and target.hostname == base.hostname
            and target.port == base.port
        )

    async def discover_capabilities(self) -> CiteCapabilities:
        if self._capabilities is not None:
            return self._capabilities

        operations: set[str] = set()
        mcp_url: str | None = None

        try:
            raw_discovery = await self._json_request(
                "GET", self._url("/.well-known/mcp.json")
            )
            discovery = CiteMcpDiscovery.model_validate(raw_discovery)
            server = discovery.mcp_servers.get("cite")
            if server is not None and self._is_same_origin(server.url):
                mcp_url = server.url
                raw_tools = await self._json_request(
                    "POST",
                    mcp_url,
                    json_body={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                )
                tools = CiteMcpToolListResponse.model_validate(raw_tools)
                operations.update(tool.name for tool in tools.result.tools)
        except (CiteRequestError, ValidationError):
            mcp_url = None

        try:
            llms_text = await self._text_request(self._url("/llms.txt"))
            operations.update(re.findall(r"`([a-z][a-z0-9_]+)`", llms_text))
        except CiteRequestError:
            pass

        graphql_url = self._url("/graphql")
        try:
            raw_graphql = await self._json_request(
                "POST",
                graphql_url,
                json_body={"query": _CAPABILITY_QUERY},
            )
            introspection = CiteGraphQLIntrospection.model_validate(raw_graphql)
            mutation_type = introspection.data.schema_.mutation_type
            if mutation_type is not None:
                operations.update(field.name for field in mutation_type.fields)
        except (CiteRequestError, ValidationError):
            pass

        self._capabilities = CiteCapabilities(
            mcp_url=mcp_url,
            graphql_url=graphql_url,
            operations=frozenset(operations),
            can_read_documents=mcp_url is not None and operations >= _DOCUMENT_OPERATIONS,
            can_read_annotations=mcp_url is not None and "list_annotations" in operations,
            can_read_relationships=mcp_url is not None and "list_relationships" in operations,
            can_write_annotations="addAnnotation" in operations,
            can_write_relationships="addRelationship" in operations,
        )
        return self._capabilities

    async def _require_operation(self, operation: str) -> CiteCapabilities:
        capabilities = await self.discover_capabilities()
        if capabilities.mcp_url is None or operation not in capabilities.operations:
            raise CiteCompatibilityError(
                f"cite target does not advertise required operation {operation}"
            )
        return capabilities

    async def _mcp_call(self, operation: str, arguments: dict[str, object]) -> object:
        capabilities = await self._require_operation(operation)
        assert capabilities.mcp_url is not None
        self._request_id += 1
        raw_response = await self._json_request(
            "POST",
            capabilities.mcp_url,
            json_body={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": operation, "arguments": arguments},
                "id": self._request_id,
            },
        )
        try:
            response = CiteMcpCallResponse.model_validate(raw_response)
            if response.result.structured_content is not None:
                return response.result.structured_content
            if len(response.result.content) != 1:
                raise ValueError("expected one text result")
            payload = cast(object, json.loads(response.result.content[0].text))
            if isinstance(payload, dict) and "error" in payload:
                raise ValueError("remote operation returned an error")
            return payload
        except (ValidationError, ValueError, json.JSONDecodeError) as error:
            message = f"cite MCP operation {operation} returned invalid data"
            raise CiteRequestError(message) from error

    async def list_documents(
        self,
        corpus_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteDocumentPage:
        payload = await self._mcp_call(
            "list_documents",
            {"corpus_slug": corpus_id, "limit": limit, "offset": offset},
        )
        try:
            return CiteDocumentPage.model_validate(payload)
        except ValidationError as error:
            raise CiteRequestError("cite list_documents returned invalid data") from error

    async def get_document(
        self,
        corpus_id: str,
        document_id: str,
        *,
        chunk_chars: int = 100_000,
    ) -> CiteDocumentText:
        if chunk_chars < 1:
            raise ValueError("chunk_chars must be positive")
        offset = 0
        chunks: list[str] = []
        first: CiteDocumentText | None = None
        while True:
            payload = await self._mcp_call(
                "get_document_text",
                {
                    "corpus_slug": corpus_id,
                    "document_slug": document_id,
                    "char_offset": offset,
                    "max_chars": chunk_chars,
                },
            )
            try:
                current = CiteDocumentText.model_validate(payload)
            except ValidationError as error:
                raise CiteRequestError("cite get_document_text returned invalid data") from error
            if current.char_offset != offset:
                raise CiteRequestError("cite get_document_text returned a non-contiguous page")
            if first is None:
                first = current
            chunks.append(current.text)
            if sum(len(chunk) for chunk in chunks) > self._max_document_chars:
                raise CiteRequestError("cite document exceeds configured character limit")
            if current.next_offset is None:
                break
            if current.next_offset <= offset:
                raise CiteRequestError("cite get_document_text returned an invalid next offset")
            offset = current.next_offset

        assert first is not None
        text = "".join(chunks)
        if len(text) != first.total_chars:
            raise CiteRequestError("cite get_document_text returned incomplete text")
        return CiteDocumentText(
            document_slug=first.document_slug,
            page_count=first.page_count,
            total_chars=first.total_chars,
            char_offset=0,
            text=text,
            next_offset=None,
            truncated=False,
        )

    async def list_annotations(
        self,
        corpus_id: str,
        document_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteAnnotationPage:
        payload = await self._mcp_call(
            "list_annotations",
            {
                "corpus_slug": corpus_id,
                "document_slug": document_id,
                "limit": limit,
                "offset": offset,
            },
        )
        try:
            return CiteAnnotationPage.model_validate(payload)
        except ValidationError as error:
            raise CiteRequestError("cite list_annotations returned invalid data") from error

    async def list_relationships(
        self,
        corpus_id: str,
        *,
        document_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteRelationshipPage:
        arguments: dict[str, object] = {
            "corpus_slug": corpus_id,
            "limit": limit,
            "offset": offset,
        }
        if document_id is not None:
            arguments["document_slug"] = document_id
        payload = await self._mcp_call("list_relationships", arguments)
        try:
            return CiteRelationshipPage.model_validate(payload)
        except ValidationError as error:
            raise CiteRequestError("cite list_relationships returned invalid data") from error

    async def _require_graphql_operation(self, operation: str) -> CiteCapabilities:
        capabilities = await self.discover_capabilities()
        if operation not in capabilities.operations:
            raise CiteCompatibilityError(
                f"cite target does not advertise required operation {operation}"
            )
        return capabilities

    async def _graphql_mutation(
        self,
        operation: str,
        query: str,
        variables: dict[str, object],
    ) -> CiteMutationReceipt:
        capabilities = await self._require_graphql_operation(operation)
        raw_response = await self._json_request(
            "POST",
            capabilities.graphql_url,
            json_body={"query": query, "variables": variables},
        )
        try:
            response = CiteGraphQLMutationResponse.model_validate(raw_response)
        except ValidationError as error:
            message = f"cite GraphQL operation {operation} returned invalid data"
            raise CiteRequestError(message) from error
        if response.errors or response.data is None:
            raise CiteRequestError(f"cite GraphQL operation {operation} failed")
        payload = (
            response.data.add_annotation
            if operation == "addAnnotation"
            else response.data.add_relationship
        )
        node = None
        if payload is not None:
            node = payload.annotation if operation == "addAnnotation" else payload.relationship
        if payload is None or not payload.ok or node is None:
            raise CiteRequestError(f"cite GraphQL operation {operation} failed")
        return CiteMutationReceipt(operation=operation, remote_id=node.id)

    async def create_annotation(
        self,
        *,
        corpus_id: str,
        document_id: str,
        annotation_label_id: str,
        raw_text: str,
        page: int,
        annotation_json: dict[str, object],
        long_description: str | None = None,
        annotation_type: str = "TOKEN_LABEL",
    ) -> CiteMutationReceipt:
        return await self._graphql_mutation(
            "addAnnotation",
            _ADD_ANNOTATION_MUTATION,
            {
                "annotationLabelId": annotation_label_id,
                "annotationType": annotation_type,
                "corpusId": corpus_id,
                "documentId": document_id,
                "json": annotation_json,
                "longDescription": long_description,
                "page": page,
                "rawText": raw_text,
            },
        )

    async def create_relationship(
        self,
        *,
        corpus_id: str,
        document_id: str,
        relationship_label_id: str,
        source_ids: list[str],
        target_ids: list[str],
    ) -> CiteMutationReceipt:
        return await self._graphql_mutation(
            "addRelationship",
            _ADD_RELATIONSHIP_MUTATION,
            {
                "corpusId": corpus_id,
                "documentId": document_id,
                "relationshipLabelId": relationship_label_id,
                "sourceIds": source_ids,
                "targetIds": target_ids,
            },
        )
