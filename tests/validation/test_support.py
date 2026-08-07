from datetime import UTC, datetime

from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    SourceRecord,
    SupportStatus,
)
from regulatory_harvest.storage import sha256_digest
from regulatory_harvest.validation import check_claim_support


def _source(text: str) -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Rule",
        retrieved_at=datetime(2026, 8, 5, tzinfo=UTC),
        content_hash=sha256_digest(text.encode()),
        media_type="text/plain",
        normalized_text=text,
    )


def _claim(text: str, quote: str) -> tuple[Claim, CitationSpan, SourceRecord]:
    source = _source(quote)
    citation = CitationSpan(
        citation_id="cite-1",
        source_id=source.source_id,
        start_char=0,
        end_char=len(quote),
        quote=quote,
    )
    claim = Claim(
        claim_id="claim-1",
        text=text,
        kind=ClaimKind.SOURCE_SUPPORTED,
        citation_ids=[citation.citation_id],
    )
    return claim, citation, source


def test_support_check_accepts_high_lexical_coverage() -> None:
    """Raising the threshold above documented behavior would reject this paraphrase."""
    claim, citation, source = _claim(
        "A controller must document material deployment risks.",
        "The controller must document all material deployment risks.",
    )
    result = check_claim_support(claim, [citation], [source])
    assert result.status is SupportStatus.SUPPORTED
    assert result.coverage >= 0.8


def test_support_check_rejects_high_coverage_polarity_inversion() -> None:
    """Ignoring negation would support the opposite legal proposition."""
    claim, citation, source = _claim(
        "The controller is not liable for documented processing fees.",
        "The controller is liable for documented processing fees.",
    )
    result = check_claim_support(claim, [citation], [source])
    assert result.status is SupportStatus.UNSUPPORTED
    assert result.reason == "polarity_mismatch"


def test_support_check_is_indeterminate_for_short_claim() -> None:
    """A ratio over too few words would produce false confidence."""
    claim, citation, source = _claim("Must report.", "A controller must report incidents.")
    result = check_claim_support(claim, [citation], [source])
    assert result.status is SupportStatus.INDETERMINATE
    assert result.reason == "too_few_content_tokens"


def test_support_check_rejects_unrelated_passage() -> None:
    """Treating any real citation as support would make this test fail."""
    claim, citation, source = _claim(
        "Controllers must retain security audit records.",
        "Agencies may publish annual fee schedules.",
    )
    result = check_claim_support(claim, [citation], [source])
    assert result.status is SupportStatus.UNSUPPORTED
    assert result.coverage < 0.6

