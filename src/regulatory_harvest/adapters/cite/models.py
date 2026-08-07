"""Typed boundary models for the public cite integration surfaces."""

from pydantic import BaseModel, ConfigDict, Field

from regulatory_harvest.models.base import StrictModel


class RemoteModel(BaseModel):
    """Permit additive fields only while parsing a remote cite response."""

    model_config = ConfigDict(extra="allow")


class CiteMcpServer(RemoteModel):
    url: str
    transport: str | None = None
    authentication: object | None = None


class CiteMcpDiscovery(RemoteModel):
    mcp_servers: dict[str, CiteMcpServer] = Field(alias="mcpServers")


class CiteMcpTool(RemoteModel):
    name: str


class CiteMcpToolList(RemoteModel):
    tools: list[CiteMcpTool] = Field(default_factory=list)


class CiteMcpToolListResponse(RemoteModel):
    result: CiteMcpToolList


class CiteMcpTextContent(RemoteModel):
    type: str
    text: str


class CiteMcpCallResult(RemoteModel):
    content: list[CiteMcpTextContent] = Field(default_factory=list)
    structured_content: dict[str, object] | None = Field(
        default=None,
        alias="structuredContent",
    )


class CiteMcpCallResponse(RemoteModel):
    result: CiteMcpCallResult


class CiteGraphQLField(RemoteModel):
    name: str


class CiteGraphQLMutationType(RemoteModel):
    fields: list[CiteGraphQLField] = Field(default_factory=list)


class CiteGraphQLSchema(RemoteModel):
    mutation_type: CiteGraphQLMutationType | None = Field(
        default=None,
        alias="mutationType",
    )


class CiteGraphQLData(RemoteModel):
    schema_: CiteGraphQLSchema = Field(alias="__schema")


class CiteGraphQLIntrospection(RemoteModel):
    data: CiteGraphQLData


class CiteCapabilities(StrictModel):
    """Operations proved available on one configured cite instance."""

    mcp_url: str | None = None
    graphql_url: str
    operations: frozenset[str] = frozenset()
    can_read_documents: bool = False
    can_read_annotations: bool = False
    can_read_relationships: bool = False
    can_write_annotations: bool = False
    can_write_relationships: bool = False


class CiteDocument(RemoteModel):
    slug: str
    title: str = ""
    description: str = ""
    page_count: int = 0
    file_type: str = "unknown"
    created: str | None = None


class CiteDocumentPage(RemoteModel):
    total_count: int
    documents: list[CiteDocument] = Field(default_factory=list)


class CiteDocumentText(RemoteModel):
    document_slug: str
    page_count: int = 0
    total_chars: int
    char_offset: int = 0
    text: str
    next_offset: int | None = None
    truncated: bool = False


class CiteAnnotationLabel(RemoteModel):
    text: str
    label_type: str | None = None


class CiteAnnotation(RemoteModel):
    id: str
    page: int
    raw_text: str = ""
    annotation_label: CiteAnnotationLabel | None = None
    structural: bool = False


class CiteAnnotationPage(RemoteModel):
    total_count: int
    annotations: list[CiteAnnotation] = Field(default_factory=list)


class CiteRelationshipNode(RemoteModel):
    annotation_id: str
    page: int
    text: str = ""


class CiteRelationship(RemoteModel):
    id: str
    label: str | None = None
    structural: bool = False
    source: list[CiteRelationshipNode] = Field(default_factory=list)
    target: list[CiteRelationshipNode] = Field(default_factory=list)


class CiteRelationshipPage(RemoteModel):
    total_count: int
    relationships: list[CiteRelationship] = Field(default_factory=list)


class CiteGraphQLMutationNode(RemoteModel):
    id: str


class CiteGraphQLMutationPayload(RemoteModel):
    ok: bool
    annotation: CiteGraphQLMutationNode | None = None
    relationship: CiteGraphQLMutationNode | None = None
    message: str | None = None


class CiteGraphQLMutationData(RemoteModel):
    add_annotation: CiteGraphQLMutationPayload | None = Field(
        default=None,
        alias="addAnnotation",
    )
    add_relationship: CiteGraphQLMutationPayload | None = Field(
        default=None,
        alias="addRelationship",
    )


class CiteGraphQLMutationResponse(RemoteModel):
    data: CiteGraphQLMutationData | None = None
    errors: list[object] = Field(default_factory=list)


class CiteMutationReceipt(StrictModel):
    operation: str
    remote_id: str
