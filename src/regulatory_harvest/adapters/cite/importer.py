"""Pure and network-orchestrated mappings from cite into Harvest evidence."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol

from pydantic import Field

from regulatory_harvest.models import (
    CitationSpan,
    FetchStatus,
    Gap,
    ReviewItem,
    SourceFailure,
    SourceRecord,
)
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.sources import normalize_content
from regulatory_harvest.storage import sha256_digest
from regulatory_harvest.validation import resolve_quote

from .client import CiteError
from .models import (
    CiteAnnotation,
    CiteAnnotationPage,
    CiteDocument,
    CiteDocumentPage,
    CiteDocumentText,
)


class CiteReadClient(Protocol):
    base_url: str

    async def list_documents(
        self,
        corpus_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteDocumentPage: ...

    async def get_document(
        self,
        corpus_id: str,
        document_id: str,
        *,
        chunk_chars: int = 100_000,
    ) -> CiteDocumentText: ...

    async def list_annotations(
        self,
        corpus_id: str,
        document_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteAnnotationPage: ...


class CiteAnnotationMapping(StrictModel):
    citation: CitationSpan | None = None
    review_item: ReviewItem | None = None


class CiteImportResult(StrictModel):
    cite_base_url: str
    corpus_id: str
    sources: list[SourceRecord] = Field(default_factory=list)
    citations: list[CitationSpan] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _source_id(base_url: str, corpus_id: str, document_id: str) -> str:
    return _stable_id("cite-source", base_url, corpus_id, document_id)


def _origin(base_url: str, corpus_id: str, document_id: str) -> str:
    return f"{base_url.rstrip('/')}#document://{corpus_id}/{document_id}"


def _external_ids(corpus_id: str, document_id: str) -> dict[str, str]:
    return {
        "cite_corpus_slug": corpus_id,
        "cite_document_slug": document_id,
    }


def map_cite_document(
    base_url: str,
    corpus_id: str,
    document: CiteDocument,
    document_text: CiteDocumentText,
    *,
    retrieved_at: datetime,
) -> SourceRecord:
    """Normalize cite's extracted text into one strict Harvest source."""
    if document.slug != document_text.document_slug:
        raise ValueError("cite document summary and text identifiers differ")
    normalized = normalize_content(document_text.text.encode("utf-8"), "text/plain")
    return SourceRecord(
        source_id=_source_id(base_url, corpus_id, document.slug),
        origin=_origin(base_url, corpus_id, document.slug),
        display_name=document.title or document.slug,
        retrieved_at=retrieved_at,
        content_hash=sha256_digest(normalized.text.encode("utf-8")),
        media_type=normalized.media_type,
        normalized_text=normalized.text,
        normalization_warnings=list(normalized.warnings),
        title=document.title or None,
        license_assertion="unknown",
        external_ids=_external_ids(corpus_id, document.slug),
    )


def map_cite_annotation(
    corpus_id: str,
    source: SourceRecord,
    annotation: CiteAnnotation,
) -> CiteAnnotationMapping:
    """Re-resolve an annotation quote against normalized Harvest text."""
    document_id = source.external_ids.get("cite_document_slug")
    if document_id is None:
        raise ValueError("source is missing cite_document_slug provenance")
    resolution = resolve_quote(source.normalized_text, annotation.raw_text)
    external_ids = {
        "cite_annotation_id": annotation.id,
        "cite_corpus_slug": corpus_id,
        "cite_document_slug": document_id,
    }
    if resolution.exact and resolution.start_char is not None and resolution.end_char is not None:
        return CiteAnnotationMapping(
            citation=CitationSpan(
                citation_id=_stable_id("cite-citation", source.source_id, annotation.id),
                source_id=source.source_id,
                start_char=resolution.start_char,
                end_char=resolution.end_char,
                quote=annotation.raw_text,
                external_ids=external_ids,
            )
        )

    code = (
        "CITE_ANNOTATION_QUOTE_AMBIGUOUS"
        if resolution.ambiguous
        else "CITE_ANNOTATION_QUOTE_UNRESOLVED"
    )
    return CiteAnnotationMapping(
        review_item=ReviewItem(
            review_id=_stable_id("cite-review", source.source_id, annotation.id),
            code=code,
            message="cite annotation text could not be mapped to one exact normalized span.",
            related_ids=[source.source_id, annotation.id],
            context={
                "page": annotation.page,
                "quote": annotation.raw_text,
                "whitespace_match": resolution.whitespace_match,
            },
        )
    )


def _failed_source(
    base_url: str,
    corpus_id: str,
    document: CiteDocument,
    retrieved_at: datetime,
) -> SourceRecord:
    return SourceRecord(
        source_id=_source_id(base_url, corpus_id, document.slug),
        origin=_origin(base_url, corpus_id, document.slug),
        display_name=document.title or document.slug,
        retrieved_at=retrieved_at,
        media_type="text/plain",
        title=document.title or None,
        license_assertion="unknown",
        fetch_status=FetchStatus.FAILED,
        error=SourceFailure(
            category="cite_document_text_unavailable",
            message="cite document text was unavailable to the configured caller.",
        ),
        external_ids=_external_ids(corpus_id, document.slug),
    )


async def _all_documents(
    client: CiteReadClient,
    corpus_id: str,
    page_size: int,
) -> tuple[list[CiteDocument], list[str]]:
    documents: list[CiteDocument] = []
    warnings: list[str] = []
    seen: set[str] = set()
    offset = 0
    total = 1
    while offset < total:
        page = await client.list_documents(corpus_id, limit=page_size, offset=offset)
        total = page.total_count
        if not page.documents and offset < total:
            warnings.append(
                f"cite document pagination stopped at offset {offset} before total {total}."
            )
            break
        offset += len(page.documents)
        for document in page.documents:
            if document.slug in seen:
                warnings.append(f"duplicate cite document {document.slug!r} was ignored.")
                continue
            seen.add(document.slug)
            documents.append(document)
    return documents, warnings


async def _all_annotations(
    client: CiteReadClient,
    corpus_id: str,
    document_id: str,
    page_size: int,
) -> tuple[list[CiteAnnotation], list[str]]:
    annotations: list[CiteAnnotation] = []
    warnings: list[str] = []
    seen: set[str] = set()
    offset = 0
    total = 1
    while offset < total:
        page = await client.list_annotations(
            corpus_id,
            document_id,
            limit=page_size,
            offset=offset,
        )
        total = page.total_count
        if not page.annotations and offset < total:
            warnings.append(
                f"cite annotation pagination for {document_id!r} stopped at offset "
                f"{offset} before total {total}."
            )
            break
        offset += len(page.annotations)
        for annotation in page.annotations:
            if annotation.id in seen:
                warnings.append(
                    f"duplicate cite annotation {annotation.id!r} on {document_id!r} was ignored."
                )
                continue
            seen.add(annotation.id)
            annotations.append(annotation)
    return annotations, warnings


async def import_cite_corpus(
    client: CiteReadClient,
    corpus_id: str,
    *,
    page_size: int = 100,
    retrieved_at: datetime | None = None,
) -> CiteImportResult:
    """Import every visible cite document and annotation with explicit gaps."""
    if page_size < 1 or page_size > 100:
        raise ValueError("page_size must be between 1 and 100")
    timestamp = retrieved_at or datetime.now(UTC)
    documents, warnings = await _all_documents(client, corpus_id, page_size)
    sources: list[SourceRecord] = []
    citations: list[CitationSpan] = []
    gaps: list[Gap] = []
    review_items: list[ReviewItem] = []

    for document in documents:
        try:
            text = await client.get_document(corpus_id, document.slug)
        except CiteError:
            source = _failed_source(client.base_url, corpus_id, document, timestamp)
            sources.append(source)
            gaps.append(
                Gap(
                    gap_id=_stable_id("cite-gap", source.source_id, "text"),
                    code="CITE_DOCUMENT_TEXT_UNAVAILABLE",
                    message="cite document text was unavailable to the configured caller.",
                    source_ids=[source.source_id],
                )
            )
            continue

        source = map_cite_document(
            client.base_url,
            corpus_id,
            document,
            text,
            retrieved_at=timestamp,
        )
        sources.append(source)
        try:
            annotations, annotation_warnings = await _all_annotations(
                client,
                corpus_id,
                document.slug,
                page_size,
            )
        except CiteError:
            gaps.append(
                Gap(
                    gap_id=_stable_id("cite-gap", source.source_id, "annotations"),
                    code="CITE_ANNOTATIONS_UNAVAILABLE",
                    message="cite annotations were unavailable to the configured caller.",
                    source_ids=[source.source_id],
                )
            )
            continue
        warnings.extend(annotation_warnings)
        for annotation in annotations:
            mapping = map_cite_annotation(corpus_id, source, annotation)
            if mapping.citation is not None:
                citations.append(mapping.citation)
            if mapping.review_item is not None:
                review_items.append(mapping.review_item)

    return CiteImportResult(
        cite_base_url=client.base_url,
        corpus_id=corpus_id,
        sources=sources,
        citations=citations,
        gaps=gaps,
        review_items=review_items,
        warnings=warnings,
    )
