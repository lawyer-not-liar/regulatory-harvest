import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regulatory_harvest.adapters.cite import (
    CiteAnnotationPage,
    CiteDocument,
    CiteDocumentPage,
    CiteDocumentText,
    CiteRequestError,
)
from regulatory_harvest.adapters.cite.importer import (
    import_cite_corpus,
    map_cite_annotation,
    map_cite_document,
)

FIXTURES = Path(__file__).parent / "fixtures"
RETRIEVED_AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _document_fixture() -> tuple[CiteDocument, CiteDocumentText]:
    payload = json.loads((FIXTURES / "document.json").read_text(encoding="utf-8"))
    return (
        CiteDocument.model_validate(payload["summary"]),
        CiteDocumentText.model_validate(payload["text"]),
    )


def test_document_mapping_normalizes_text_and_preserves_cite_identity() -> None:
    """Losing remote identity or hashing pre-normalized text would break provenance."""
    summary, text = _document_fixture()

    source = map_cite_document(
        "https://cite.example",
        "public-corpus",
        summary,
        text,
        retrieved_at=RETRIEVED_AT,
    )

    assert source.normalized_text == "A controller must document material risks."
    assert source.content_hash == (
        "9a727256506b87b1b23e6cb8056193aa5dbce0b998565c2fa3c15961968e8980"
    )
    assert source.origin == (
        "https://cite.example#document://public-corpus/public-rule"
    )
    assert source.external_ids == {
        "cite_corpus_slug": "public-corpus",
        "cite_document_slug": "public-rule",
    }
    assert source.media_type == "text/plain"
    assert source.title == "Public Rule"


def test_annotation_mapping_re_resolves_exact_quote_after_normalization() -> None:
    """Trusting remote offsets after newline normalization would cite the wrong slice."""
    summary, text = _document_fixture()
    source = map_cite_document(
        "https://cite.example",
        "public-corpus",
        summary,
        text,
        retrieved_at=RETRIEVED_AT,
    )
    payload = json.loads((FIXTURES / "annotations.json").read_text(encoding="utf-8"))
    annotation = CiteAnnotationPage.model_validate(payload).annotations[0]

    mapping = map_cite_annotation("public-corpus", source, annotation)

    assert mapping.review_item is None
    assert mapping.citation is not None
    assert mapping.citation.start_char == 13
    assert mapping.citation.end_char == 42
    assert source.normalized_text[13:42] == mapping.citation.quote
    assert mapping.citation.external_ids == {
        "cite_annotation_id": "101",
        "cite_corpus_slug": "public-corpus",
        "cite_document_slug": "public-rule",
    }


def test_unresolved_annotation_becomes_review_item_not_citation() -> None:
    """Fabricating an offset for absent text would create false evidence."""
    summary, text = _document_fixture()
    source = map_cite_document(
        "https://cite.example",
        "public-corpus",
        summary,
        text,
        retrieved_at=RETRIEVED_AT,
    )
    payload = json.loads((FIXTURES / "annotations.json").read_text(encoding="utf-8"))
    annotation = CiteAnnotationPage.model_validate(payload).annotations[1]

    mapping = map_cite_annotation("public-corpus", source, annotation)

    assert mapping.citation is None
    assert mapping.review_item is not None
    assert mapping.review_item.code == "CITE_ANNOTATION_QUOTE_UNRESOLVED"
    assert mapping.review_item.related_ids == [source.source_id, "102"]


class _PagedCiteClient:
    base_url = "https://cite.example"

    def __init__(self) -> None:
        self._summary, self._text = _document_fixture()
        self._duplicate = self._summary.model_copy(update={"title": "Duplicate page entry"})
        self._unavailable = self._summary.model_copy(
            update={"slug": "private-rule", "title": "Unavailable Rule"}
        )
        self._same_content = self._summary.model_copy(
            update={"slug": "mirror-rule", "title": "Mirrored Rule"}
        )

    async def list_documents(
        self, _corpus_id: str, *, limit: int = 100, offset: int = 0
    ) -> CiteDocumentPage:
        del limit
        if offset == 0:
            return CiteDocumentPage(
                total_count=4,
                documents=[self._summary, self._duplicate],
            )
        return CiteDocumentPage(
            total_count=4,
            documents=[self._unavailable, self._same_content],
        )

    async def get_document(
        self, _corpus_id: str, document_id: str, *, chunk_chars: int = 100_000
    ) -> CiteDocumentText:
        del chunk_chars
        if document_id == "private-rule":
            raise CiteRequestError("not available")
        return self._text.model_copy(update={"document_slug": document_id})

    async def list_annotations(
        self,
        _corpus_id: str,
        document_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> CiteAnnotationPage:
        del document_id, limit
        payload = json.loads((FIXTURES / "annotations.json").read_text(encoding="utf-8"))
        page = CiteAnnotationPage.model_validate(payload)
        if offset == 0:
            return page.model_copy(update={"total_count": 3})
        return CiteAnnotationPage(
            total_count=3,
            annotations=[page.annotations[0]],
        )


@pytest.mark.asyncio
async def test_import_paginates_deduplicates_ids_and_keeps_same_content_origins() -> None:
    """Pagination bugs or content deduplication could silently discard distinct authorities."""
    result = await import_cite_corpus(
        _PagedCiteClient(),  # type: ignore[arg-type]
        "public-corpus",
        page_size=2,
        retrieved_at=RETRIEVED_AT,
    )

    assert [source.external_ids["cite_document_slug"] for source in result.sources] == [
        "public-rule",
        "private-rule",
        "mirror-rule",
    ]
    assert result.sources[0].content_hash == result.sources[2].content_hash
    assert result.sources[0].origin != result.sources[2].origin
    assert result.sources[1].fetch_status.value == "failed"
    assert [gap.code for gap in result.gaps] == ["CITE_DOCUMENT_TEXT_UNAVAILABLE"]
    assert len(result.citations) == 2
    assert len(result.review_items) == 2
    assert any("duplicate cite document" in warning for warning in result.warnings)
