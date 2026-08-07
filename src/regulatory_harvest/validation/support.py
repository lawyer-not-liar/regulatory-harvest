"""Transparent lexical claim-support checks."""

import re
from dataclasses import dataclass

from regulatory_harvest.models import CitationSpan, Claim, SourceRecord, SupportStatus

_TOKEN_RE = re.compile(r"[^\W_]+(?:[-'][^\W_]+)*", flags=re.UNICODE)
_STOP_WORDS = {
    "a",
    "all",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "before",
    "by",
    "for",
    "from",
    "in",
    "is",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "with",
}
_NEGATION_MARKERS = {"no", "not", "never", "without"}


@dataclass(frozen=True, slots=True)
class SupportCheck:
    status: SupportStatus
    coverage: float
    reason: str


def _content_tokens(text: str) -> list[str]:
    return [
        token
        for token in _TOKEN_RE.findall(text.casefold())
        if token not in _STOP_WORDS
    ]


def check_claim_support(
    claim: Claim,
    citations: list[CitationSpan],
    sources: list[SourceRecord],
) -> SupportCheck:
    """Apply a documented lexical floor without claiming legal entailment."""
    claim_tokens = _content_tokens(claim.text)
    if len(claim_tokens) < 4:
        return SupportCheck(
            status=SupportStatus.INDETERMINATE,
            coverage=0.0,
            reason="too_few_content_tokens",
        )

    source_by_id = {source.source_id: source for source in sources}
    supported_text: list[str] = []
    for citation in citations:
        source = source_by_id.get(citation.source_id)
        if source is None:
            continue
        if source.normalized_text[citation.start_char : citation.end_char] != citation.quote:
            continue
        supported_text.append(citation.quote)
    support_tokens = set(_content_tokens(" ".join(supported_text)))
    if not support_tokens:
        return SupportCheck(
            status=SupportStatus.UNSUPPORTED,
            coverage=0.0,
            reason="no_valid_support_text",
        )

    overlap = sum(token in support_tokens for token in claim_tokens)
    coverage = overlap / len(claim_tokens)
    claim_negation = set(claim_tokens) & _NEGATION_MARKERS
    support_negation = support_tokens & _NEGATION_MARKERS
    if coverage >= 0.80 and claim_negation != support_negation:
        return SupportCheck(
            status=SupportStatus.UNSUPPORTED,
            coverage=coverage,
            reason="polarity_mismatch",
        )
    if coverage >= 0.60:
        return SupportCheck(
            status=SupportStatus.SUPPORTED,
            coverage=coverage,
            reason="lexical_coverage",
        )
    return SupportCheck(
        status=SupportStatus.UNSUPPORTED,
        coverage=coverage,
        reason="low_lexical_coverage",
    )

