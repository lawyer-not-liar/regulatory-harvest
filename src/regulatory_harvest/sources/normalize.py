"""Source content normalization with stable character offsets."""

import unicodedata
from dataclasses import dataclass
from io import BytesIO

from bs4 import BeautifulSoup
from pypdf import PdfReader


class NormalizationError(ValueError):
    """Raised when source bytes cannot be normalized without hiding data loss."""


@dataclass(frozen=True, slots=True)
class NormalizedContent:
    text: str
    media_type: str
    warnings: tuple[str, ...] = ()


def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise NormalizationError("text source is not valid UTF-8") from error


def _normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()

    normalized: list[str] = []
    previous_blank = False
    for line in lines:
        blank = not line
        if blank and previous_blank:
            continue
        normalized.append(line)
        previous_blank = blank
    return "\n".join(normalized)


def _normalize_html(data: bytes) -> NormalizedContent:
    soup = BeautifulSoup(_decode_utf8(data), "html.parser")
    for element in soup(["script", "style", "noscript", "template"]):
        element.decompose()
    lines = [line.strip() for line in soup.get_text("\n").splitlines() if line.strip()]
    return NormalizedContent(text=_normalize_text("\n".join(lines)), media_type="text/html")


def _normalize_pdf(data: bytes) -> NormalizedContent:
    try:
        reader = PdfReader(BytesIO(data), strict=True)
        page_text: list[str] = []
        warnings: list[str] = []
        for index, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            if not text.strip():
                warnings.append(f"page {index} contained no extractable text")
            page_text.append(text)
    except Exception as error:
        raise NormalizationError("PDF source could not be parsed") from error
    return NormalizedContent(
        text=_normalize_text("\n\n".join(page_text)),
        media_type="application/pdf",
        warnings=tuple(warnings),
    )


def normalize_content(data: bytes, media_type: str) -> NormalizedContent:
    """Normalize supported bytes while preserving intra-line character positions."""
    normalized_media_type = media_type.partition(";")[0].strip().lower()
    if normalized_media_type in {"text/plain", "text/markdown"}:
        return NormalizedContent(
            text=_normalize_text(_decode_utf8(data)), media_type=normalized_media_type
        )
    if normalized_media_type in {"text/html", "application/xhtml+xml"}:
        return _normalize_html(data)
    if normalized_media_type == "application/pdf":
        return _normalize_pdf(data)
    raise NormalizationError(f"unsupported media type: {normalized_media_type or 'unknown'}")
