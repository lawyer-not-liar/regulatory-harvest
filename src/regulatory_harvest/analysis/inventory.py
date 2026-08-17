"""Deterministic provision leads over complete normalized source text."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any

PROVISION_LEADS_VERSION = "provision-leads-v2"
PROVISION_LEADS_NOTICE = "Heuristic research leads, not legal conclusions."
MAX_PRIORITY_LEADS_PER_TOPIC = 3

_HEADING = re.compile(
    r"^\s*(?:"
    r"(?:article|section|chapter|part|title|schedule|annex)\s+[A-Za-z0-9IVXLC.-]+"
    r"|§+\s*[A-Za-z0-9.-]+"
    r"|第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*条"
    r"|المادة\s*\(?[0-9\u0660-\u0669]+\)?"
    r")[^\n]{0,180}$",
    re.IGNORECASE,
)
_BLOCK = re.compile(r"\S(?:.*?\S)?(?=\n[ \t]*\n|[ \t\r\n]*\Z)", re.DOTALL)
_NUMERIC_SIGNAL = re.compile(r"(?:[$€£¥]\s*\d|\b\d[\d,.]*\s*%?\b)")
_PROVISION_BOUNDARY = re.compile(r"(?:[.;!?][ \t]+|\n+)")

_TOPIC_PRIORITY = {
    "status": 15,
    "scope_actors": 10,
    "definitions": 6,
    "duties": 10,
    "exceptions": 12,
    "deadlines": 14,
    "enforcement": 16,
    "remedies_penalties": 20,
    "appeals": 8,
    "implementation": 10,
}

_TOPIC_SPECS: tuple[tuple[str, str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "status",
        "status",
        (
            re.compile(
                r"\b(?:takes?\s+effect|effective\s+(?:on|date)|enters?\s+into\s+force|"
                r"enacted|operative|repeal(?:ed|s)?|rescinded|supersed(?:e|ed|es|ing)|"
                r"stayed|enjoined|expir(?:e|es|ed|ation))\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "scope_actors",
        "scope",
        (
            re.compile(
                r"\b(?:appl(?:y|ies|icable)\s+to|covered\s+(?:person|operator|entity|"
                r"provider|business)|regulated\s+(?:person|entity)|subject\s+to\s+this|"
                r"territorial\s+scope|extraterritorial|jurisdiction\s+over)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "definitions",
        "scope",
        (
            re.compile(
                r"\b(?:definitions?|for\s+purposes\s+of|means\s+(?:a|an|any|the)|"
                r"is\s+defined\s+as|term\s+.+?\s+means)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "duties",
        "requirements",
        (
            re.compile(
                r"\b(?:must|shall|required\s+to|may\s+not|shall\s+not|prohibit(?:ed|s)?|"
                r"duty\s+to|obligation\s+to)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "exceptions",
        "scope",
        (
            re.compile(
                r"\b(?:does\s+not\s+apply|except(?:ion|ions)?|exempt(?:ion|ions|ed)?|"
                r"unless|threshold|safe\s+harbor|defen[cs]e)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "deadlines",
        "deadlines",
        (
            re.compile(
                r"\b(?:within\s+\d+\s+(?:business\s+)?(?:days?|months?|years?)|"
                r"no\s+later\s+than|deadline|transition\s+period|compliance\s+date|"
                r"by\s+[A-Z][a-z]+\s+\d{1,2},\s+\d{4})\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "enforcement",
        "enforcement",
        (
            re.compile(
                r"\b(?:enforc(?:e|es|ed|ement)|investigat(?:e|es|ed|ion)|"
                r"administrative\s+action|civil\s+action|criminal\s+(?:action|prosecution)|"
                r"attorney\s+general|bring\s+an?\s+(?:action|proceeding)|"
                r"issue\s+an?\s+order)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "remedies_penalties",
        "enforcement",
        (
            re.compile(
                r"\b(?:civil\s+penalt(?:y|ies)|criminal\s+penalt(?:y|ies)|"
                r"administrative\s+fine|fine\s+of|damages|injunction|injunctive\s+relief|"
                r"remed(?:y|ies)|restitution|forfeiture|liable\s+for|subject\s+to\s+(?:a\s+)?"
                r"(?:fine|penalty))\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "appeals",
        "enforcement",
        (
            re.compile(
                r"\b(?:appeal(?:s|ed|ing)?|judicial\s+review|petition\s+for\s+review|"
                r"review\s+of\s+(?:an?\s+)?order)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "implementation",
        "implementation",
        (
            re.compile(
                r"\b(?:implementing\s+regulations?|compliance\s+program|recordkeeping|"
                r"records?\s+retention|reporting\s+requirement|policies\s+and\s+procedures|"
                r"designate\s+(?:an?|the)|training\s+program)\b",
                re.IGNORECASE,
            ),
        ),
    ),
)


def _stable_lead_id(source_id: str, topic: str, start: int, end: int, excerpt: str) -> str:
    identity = "\0".join((source_id, topic, str(start), str(end), excerpt)).encode()
    return f"lead_{hashlib.sha256(identity).hexdigest()[:24]}"


def _heading(block_text: str) -> str | None:
    first_line = block_text.splitlines()[0].strip()
    return first_line if _HEADING.fullmatch(first_line) else None


def _lead_span(
    block_start: int,
    block_end: int,
    match_starts: Sequence[int],
    match_ends: Sequence[int],
) -> tuple[int, int]:
    if block_end - block_start <= 1_600:
        return block_start, block_end
    first = min(match_starts)
    last = max(match_ends)
    return max(block_start, first - 400), min(block_end, last + 800)


def _match_partitions(
    text: str,
    block_start: int,
    block_end: int,
    matches: Sequence[re.Match[str]],
) -> list[tuple[int, int, re.Match[str]]]:
    """Partition one provision so each signal remains independently reviewable."""
    ordered = sorted(
        {(match.start(), match.end(), match.group(0)): match for match in matches}.values(),
        key=lambda match: (match.start(), match.end(), match.group(0).casefold()),
    )
    absolute = [
        (block_start + match.start(), block_start + match.end(), match)
        for match in ordered
    ]
    boundaries = [block_start]
    for (_, previous_end, _), (next_start, _, _) in pairwise(absolute):
        separator = _PROVISION_BOUNDARY.search(text, previous_end, next_start)
        boundaries.append(
            separator.end() if separator is not None else (previous_end + next_start) // 2
        )
    boundaries.append(block_end)
    return [
        (boundaries[index], boundaries[index + 1], match)
        for index, (_, _, match) in enumerate(absolute)
    ]


def _source_group(source: Mapping[str, object], source_id: str) -> str:
    for field in ("canonical_url", "content_hash"):
        value = source.get(field)
        if isinstance(value, str) and value:
            return value
    return source_id


def _priority_score(
    lead: Mapping[str, Any],
    source: Mapping[str, object],
) -> int:
    raw_source_role = source.get("source_role")
    raw_source_quality = source.get("source_quality")
    source_role = raw_source_role if isinstance(raw_source_role, str) else ""
    source_quality = raw_source_quality if isinstance(raw_source_quality, str) else ""
    score: int = {
        "official_primary": 50,
        "secondary": -10,
        "commentary_analysis": -100,
    }.get(source_role, 0)
    score += {
        "primary": 40,
        "secondary": -5,
        "unusable": -100,
    }.get(source_quality, 0)
    score += _TOPIC_PRIORITY.get(str(lead.get("topic")), 0)
    score += 15 if lead.get("heading") is not None else 0
    signals = lead.get("signals")
    score += min(len(signals), 5) if isinstance(signals, list) else 0
    excerpt = lead.get("excerpt")
    if isinstance(excerpt, str) and _NUMERIC_SIGNAL.search(excerpt):
        score += 10
    return score


def _mark_priority_leads(
    leads: list[dict[str, Any]],
    sources: Sequence[Mapping[str, object]],
) -> None:
    source_by_id = {
        source_id: source
        for source in sources
        if isinstance((source_id := source.get("source_id")), str)
    }
    selected_ids: set[str] = set()
    topics = sorted({str(lead["topic"]) for lead in leads})
    for topic in topics:
        candidates = [
            lead
            for lead in leads
            if lead["topic"] == topic
            and source_by_id.get(lead["source_id"], {}).get("source_role")
            != "commentary_analysis"
            and source_by_id.get(lead["source_id"], {}).get("source_quality")
            != "unusable"
        ]
        ranked = sorted(
            candidates,
            key=lambda lead: (
                -_priority_score(lead, source_by_id.get(lead["source_id"], {})),
                lead["source_id"],
                lead["start_char"],
                lead["lead_id"],
            ),
        )
        chosen: list[dict[str, Any]] = []
        used_groups: set[str] = set()
        for lead in ranked:
            source = source_by_id.get(lead["source_id"], {})
            group = _source_group(source, lead["source_id"])
            if group in used_groups:
                continue
            chosen.append(lead)
            used_groups.add(group)
            if len(chosen) == MAX_PRIORITY_LEADS_PER_TOPIC:
                break
        if len(chosen) < MAX_PRIORITY_LEADS_PER_TOPIC:
            chosen_ids = {str(lead["lead_id"]) for lead in chosen}
            for lead in ranked:
                if lead["lead_id"] in chosen_ids:
                    continue
                chosen.append(lead)
                if len(chosen) == MAX_PRIORITY_LEADS_PER_TOPIC:
                    break
        selected_ids.update(str(lead["lead_id"]) for lead in chosen)
    for lead in leads:
        lead["review_required"] = lead["lead_id"] in selected_ids


def build_evidence_inventory(sources: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Return inclusive, non-conclusive research leads for successful sources."""
    leads: list[dict[str, Any]] = []
    source_count = 0
    for source in sources:
        if source.get("fetch_status") != "succeeded":
            continue
        source_id = source.get("source_id")
        text = source.get("normalized_text")
        if not isinstance(source_id, str) or not source_id or not isinstance(text, str) or not text:
            continue
        source_count += 1
        for block_match in _BLOCK.finditer(text):
            block_start, block_end = block_match.span()
            block_text = block_match.group(0)
            heading = _heading(block_text)
            for topic, issue_category, patterns in _TOPIC_SPECS:
                matches = [
                    match
                    for pattern in patterns
                    for match in pattern.finditer(block_text)
                ]
                if not matches:
                    continue
                for partition_start, partition_end, match in _match_partitions(
                    text, block_start, block_end, matches
                ):
                    match_start = block_start + match.start()
                    match_end = block_start + match.end()
                    start, end = _lead_span(
                        partition_start,
                        partition_end,
                        [match_start],
                        [match_end],
                    )
                    excerpt = text[start:end]
                    leads.append(
                        {
                            "lead_id": _stable_lead_id(
                                source_id, topic, start, end, excerpt
                            ),
                            "source_id": source_id,
                            "topic": topic,
                            "issue_category": issue_category,
                            "start_char": start,
                            "end_char": end,
                            "heading": heading,
                            "excerpt": excerpt,
                            "signals": [match.group(0).strip().casefold()],
                        }
                    )
    leads.sort(key=lambda item: (item["source_id"], item["start_char"], item["topic"]))
    _mark_priority_leads(leads, sources)
    topic_counts = Counter(str(lead["topic"]) for lead in leads)
    priority_topic_counts = Counter(
        str(lead["topic"]) for lead in leads if lead["review_required"]
    )
    return {
        "inventory_version": PROVISION_LEADS_VERSION,
        "notice": PROVISION_LEADS_NOTICE,
        "source_count": source_count,
        "lead_count": len(leads),
        "priority_lead_count": sum(priority_topic_counts.values()),
        "priority_topic_counts": dict(sorted(priority_topic_counts.items())),
        "priority_cap_per_topic": MAX_PRIORITY_LEADS_PER_TOPIC,
        "topic_counts": dict(sorted(topic_counts.items())),
        "leads": leads,
    }
