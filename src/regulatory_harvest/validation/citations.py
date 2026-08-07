"""Exact quote resolution against normalized source text."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QuoteResolution:
    start_char: int | None
    end_char: int | None
    exact: bool
    ambiguous: bool
    whitespace_match: bool
    matches: tuple[tuple[int, int], ...] = ()


def _all_matches(source_text: str, quote: str) -> tuple[tuple[int, int], ...]:
    matches: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = source_text.find(quote, cursor)
        if start < 0:
            break
        matches.append((start, start + len(quote)))
        cursor = start + 1
    return tuple(matches)


def resolve_quote(
    source_text: str, quote: str, occurrence: int | None = None
) -> QuoteResolution:
    """Resolve an exact quote, requiring an occurrence for repeated text."""
    if not quote:
        return QuoteResolution(None, None, False, False, False)
    matches = _all_matches(source_text, quote)
    whitespace_match = " ".join(quote.split()) in " ".join(source_text.split())
    if len(matches) == 1 and occurrence in {None, 1}:
        start, end = matches[0]
        return QuoteResolution(start, end, True, False, whitespace_match, matches)
    if occurrence is not None and 1 <= occurrence <= len(matches):
        start, end = matches[occurrence - 1]
        return QuoteResolution(start, end, True, len(matches) > 1, whitespace_match, matches)
    return QuoteResolution(
        None,
        None,
        False,
        len(matches) > 1,
        whitespace_match,
        matches,
    )

