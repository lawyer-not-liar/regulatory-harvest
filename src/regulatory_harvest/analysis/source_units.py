"""Deterministic, source-derived coverage units over normalized source text."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

SOURCE_UNIT_INVENTORY_VERSION = "source-units-v1"
MAX_SOURCE_UNIT_CHARS = 1_600

_NONBLANK_BLOCK = re.compile(r"\S(?:.*?\S)?(?=\n[ \t]*\n|[ \t\r\n]*\Z)", re.DOTALL)
_ENUMERATOR = re.compile(
    r"^[ \t]*(?:"
    r"\(\s*(?:\d+|[A-Za-z]|[IVXLCDMivxlcdm]+)\s*\)"
    r"|(?:\d+|[A-Za-z]|[IVXLCDMivxlcdm]+)[.)、:\uFF1A]"
    r"|第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*(?:条|條|項|款|節)"
    r"|المادة\s*\(?[0-9\u0660-\u0669]+\)?"
    r")",
    re.MULTILINE,
)
_SENTENCE_TERMINATORS = frozenset(".?!;。\uFF01\uFF1F؛।")
_HEADING = re.compile(
    r"^[ \t]*(?:"
    r"(?:article|artículo|section|chapter|part|title|schedule|annex)\s+"
    r"[A-Za-z0-9IVXLC.-]+"
    r"|§+\s*[A-Za-z0-9.-]+"
    r"|第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*条"
    r"|المادة\s*\(?[0-9\u0660-\u0669]+\)?"
    r")[^\n]{0,180}$",
    re.IGNORECASE,
)


def build_source_unit_inventory(sources: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Build the complete reviewable-unit inventory for eligible source records."""
    units: list[dict[str, Any]] = []
    eligible_source_count = 0
    for source in sources:
        if not _source_is_eligible(source):
            continue
        source_id = source.get("source_id")
        text = source.get("normalized_text")
        if not isinstance(source_id, str) or not source_id or not isinstance(text, str):
            continue
        eligible_source_count += 1
        for start, end, heading, locator in _partition_source(text):
            excerpt = text[start:end]
            units.append(
                {
                    "unit_id": _stable_unit_id(source_id, start, end, excerpt),
                    "source_id": source_id,
                    "start_char": start,
                    "end_char": end,
                    "heading": heading,
                    "locator": locator,
                    "excerpt": excerpt,
                    "coverage_required": True,
                }
            )
    units.sort(key=lambda unit: (unit["source_id"], unit["start_char"], unit["unit_id"]))
    return {
        "inventory_version": SOURCE_UNIT_INVENTORY_VERSION,
        "eligible_source_count": eligible_source_count,
        "unit_count": len(units),
        "required_unit_count": len(units),
        "units": units,
    }


def _source_is_eligible(source: Mapping[str, object]) -> bool:
    return (
        source.get("fetch_status") == "succeeded"
        and source.get("source_role") != "commentary_analysis"
        and source.get("source_quality") != "unusable"
    )


def _stable_unit_id(source_id: str, start: int, end: int, excerpt: str) -> str:
    identity = "\0".join((source_id, str(start), str(end), excerpt)).encode()
    return f"unit_{hashlib.sha256(identity).hexdigest()[:24]}"


def _partition_source(text: str) -> list[tuple[int, int, str | None, str]]:
    spans: list[tuple[int, int, str | None]] = []
    for block in _NONBLANK_BLOCK.finditer(text):
        block_start, block_end = block.span()
        spans.extend(_partition_block(text, block_start, block_end))

    expanded: list[tuple[int, int, str | None, str]] = []
    for start, end, heading in spans:
        for chunk_start, chunk_end in _split_long_span(text, start, end):
            expanded.append(
                (chunk_start, chunk_end, heading, f"chars:{chunk_start}-{chunk_end}"))
    _assert_exact_partition(text, expanded)
    return expanded


def _partition_block(
    text: str,
    block_start: int,
    block_end: int,
) -> list[tuple[int, int, str | None]]:
    heading, body_start = _standalone_heading(text, block_start, block_end)
    body_ranges = _split_at_enumerators(text, body_start, block_end)
    spans: list[tuple[int, int, str | None]] = []
    for range_start, range_end in body_ranges:
        spans.extend(
            (start, end, heading)
            for start, end in _split_clauses(text, range_start, range_end)
        )

    if heading is not None and spans:
        _, first_end, _ = spans[0]
        if first_end - block_start <= MAX_SOURCE_UNIT_CHARS:
            spans[0] = (block_start, first_end, heading)
        else:
            spans.insert(0, (block_start, body_start, heading))
    elif heading is not None:
        spans.append((block_start, block_end, heading))
    return spans


def _standalone_heading(text: str, start: int, end: int) -> tuple[str | None, int]:
    newline = text.find("\n", start, end)
    if newline == -1:
        return None, start
    first_line = text[start:newline].strip()
    if not first_line or not _HEADING.fullmatch(first_line):
        return None, start
    body_start = newline + 1
    while body_start < end and text[body_start].isspace():
        body_start += 1
    return first_line, body_start


def _split_at_enumerators(text: str, start: int, end: int) -> list[tuple[int, int]]:
    starts = [start]
    for match in _ENUMERATOR.finditer(text, start, end):
        if match.start() > start:
            starts.append(match.start())
    return [
        (range_start, range_end)
        for range_start, range_end in zip(starts, [*starts[1:], end], strict=True)
    ]


def _split_clauses(text: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    current_start = start
    for index in range(start, end):
        if text[index] in _SENTENCE_TERMINATORS:
            spans.append((current_start, index + 1))
            current_start = index + 1
    if current_start < end:
        spans.append((current_start, end))
    return [span for span in spans if any(not char.isspace() for char in text[span[0] : span[1]])]


def _split_long_span(text: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    current_start = start
    while end - current_start > MAX_SOURCE_UNIT_CHARS:
        limit = current_start + MAX_SOURCE_UNIT_CHARS
        split_at = _last_boundary(text, current_start, limit)
        if split_at is None:
            split_at = _next_boundary(text, limit, end)
        if split_at is None:
            split_at = end
        spans.append((current_start, split_at))
        current_start = split_at
    if current_start < end:
        spans.append((current_start, end))
    return spans


def _last_boundary(text: str, start: int, limit: int) -> int | None:
    for index in range(limit - 1, start, -1):
        if _is_long_unit_boundary(text[index]):
            return index + 1
    return None


def _next_boundary(text: str, start: int, end: int) -> int | None:
    for index in range(start, end):
        if _is_long_unit_boundary(text[index]):
            return index + 1
    return None


def _is_long_unit_boundary(character: str) -> bool:
    return character.isspace() or unicodedata.category(character).startswith("P")


def _assert_exact_partition(
    text: str,
    spans: Sequence[tuple[int, int, str | None, str]],
) -> None:
    claimed = [False] * len(text)
    previous_end = 0
    for start, end, _, _ in spans:
        assert 0 <= start < end <= len(text)
        assert previous_end <= start
        previous_end = end
        for index in range(start, end):
            if not text[index].isspace():
                assert not claimed[index]
                claimed[index] = True
    assert all(character.isspace() or claimed[index] for index, character in enumerate(text))
