from hypothesis import given
from hypothesis import strategies as st

from regulatory_harvest.validation import resolve_quote


def test_unique_quote_resolves_exact_half_open_offsets() -> None:
    """An off-by-one resolver would make the returned slice differ from the quote."""
    source = "A controller must document risks."
    result = resolve_quote(source, "must document")
    assert result.start_char == 13
    assert result.end_char == 26
    assert result.exact is True
    assert result.ambiguous is False


def test_repeated_quote_without_occurrence_is_ambiguous() -> None:
    """Silently choosing the first repeated quote would make this test fail."""
    result = resolve_quote("must act; must report", "must")
    assert result.ambiguous is True
    assert result.start_char is None
    assert result.matches == ((0, 4), (10, 14))


def test_repeated_quote_uses_one_based_occurrence() -> None:
    """Ignoring the proposed occurrence would cite the wrong statutory passage."""
    result = resolve_quote("must act; must report", "must", occurrence=2)
    assert (result.start_char, result.end_char) == (10, 14)
    assert result.exact is True


def test_whitespace_match_is_diagnostic_not_exact() -> None:
    """Promoting normalized whitespace to exact would hide changed source text."""
    result = resolve_quote("must\n document risks", "must document risks")
    assert result.exact is False
    assert result.whitespace_match is True
    assert result.start_char is None


@given(
    source=st.text(min_size=1, max_size=80),
    start=st.integers(min_value=0, max_value=79),
    width=st.integers(min_value=1, max_value=20),
)
def test_resolved_occurrence_always_slices_to_original_quote(
    source: str, start: int, width: int
) -> None:
    """Any Unicode offset mutation would violate this slice invariant."""
    if start >= len(source):
        return
    quote = source[start : min(len(source), start + width)]
    if not quote.strip():
        return
    matches: list[int] = []
    cursor = 0
    while True:
        match = source.find(quote, cursor)
        if match < 0:
            break
        matches.append(match)
        cursor = match + 1
    occurrence = matches.index(start) + 1

    result = resolve_quote(source, quote, occurrence=occurrence)

    assert result.start_char is not None
    assert result.end_char is not None
    assert source[result.start_char : result.end_char] == quote

