import unicodedata
from io import BytesIO

import pytest
from pypdf import PdfWriter

from regulatory_harvest.sources import NormalizationError, normalize_content


def test_html_normalization_removes_executable_and_style_content() -> None:
    """Leaving script or style text would contaminate the evidence corpus."""
    normalized = normalize_content(
        b"<h1>Rule</h1><script>alert(1)</script><style>.x{}</style>"
        b"<p>A controller must act.</p>",
        "text/html",
    )
    assert normalized.text == "Rule\nA controller must act."
    assert "alert" not in normalized.text


def test_text_normalization_preserves_intraline_spacing_and_uses_nfc() -> None:
    """Collapsing intra-line spaces or preserving decomposed Unicode would shift offsets."""
    decomposed = unicodedata.normalize("NFD", "Café")
    normalized = normalize_content(
        f"{decomposed}  rule  \r\n\r\n\r\nMust act.\r\n".encode(),
        "text/plain",
    )
    assert normalized.text == "Café  rule\n\nMust act."


def test_invalid_utf8_fails_visibly() -> None:
    """Replacement decoding would hide that quote offsets no longer match the source."""
    with pytest.raises(NormalizationError, match="UTF-8"):
        normalize_content(b"rule\xfftext", "text/plain")


def test_unsupported_media_type_fails_visibly() -> None:
    """Treating arbitrary binary data as text would create fabricated evidence."""
    with pytest.raises(NormalizationError, match="unsupported"):
        normalize_content(b"binary", "application/octet-stream")


def test_pdf_normalization_reports_pages_without_extractable_text() -> None:
    """Dropping page warnings would make a blank PDF appear evidentially complete."""
    output = BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(output)

    normalized = normalize_content(output.getvalue(), "application/pdf")

    assert normalized.text == ""
    assert normalized.media_type == "application/pdf"
    assert normalized.warnings == ("page 1 contained no extractable text",)
