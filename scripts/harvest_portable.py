#!/usr/bin/env python3
"""Standard-library Regulatory Harvest runner for offline agent sandboxes."""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import ipaddress
import json
import math
import mimetypes
import os
import re
import shutil
import socket
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from html.parser import HTMLParser
from pathlib import Path, PureWindowsPath
from typing import Any, ClassVar, Never, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

GENERATOR_VERSION = "0.1.0"
MAX_SOURCE_BYTES = 10 * 1024 * 1024
EVAL_EXIT_SUCCESS = 0
EVAL_EXIT_INPUT = 2
EVAL_EXIT_INCONCLUSIVE = 3
EVAL_EXIT_FAIL = 4
EVAL_EXIT_INTEGRITY = 5
EVAL_EXIT_ENGINE_PAUSED = 6
_EVAL_RESPONSE_MAX_BYTES = 1024 * 1024
_EVAL_RESPONSE_MAX_DEPTH = 64
STAGES = ("collect", "organize", "map", "build", "inspect", "note", "export")
DISCLAIMER = (
    "AI-assisted research work product. A qualified attorney must verify the sources, "
    "analysis, currentness, and applicability before relying on it or delivering legal advice."
)
SOURCE_QUALITIES = {"primary", "secondary", "unknown", "unusable"}
SOURCE_ROLES = {"official_primary", "secondary", "commentary_analysis"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CLAIM_KINDS = {"source_supported", "analysis"}
ENFORCEMENT_CLAIM_ROLES = {"trigger", "consequence"}
LEAD_REVIEW_DISPOSITIONS = {"gap", "not_material"}
COVERAGE_DISPOSITIONS = {"covered", "gap", "not_material"}
COVERAGE_ELEMENT_STATUSES = {"stated", "not_applicable", "not_established"}
UNIT_DIMENSION_DISPOSITIONS = {"mapped", "not_present", "gap", "not_material"}
LEAD_DISPOSITIONS_V2 = {"mapped", "gap", "not_material"}
ATOM_MATERIALITIES = {"critical", "material", "supporting"}
ATOM_RELATIONSHIP_TYPES = {
    "qualifies",
    "exception_to",
    "deadline_for",
    "enforces",
    "triggered_by",
    "consequence_of",
    "appeals_from",
    "defines",
}
PROPOSITION_TYPES = {
    "status",
    "definition",
    "scope",
    "right",
    "duty",
    "prohibition",
    "exception",
    "deadline",
    "enforcement_trigger",
    "enforcement_route",
    "remedy",
    "penalty",
    "appeal",
    "implementation",
    "other",
}
BRIEF_BLOCK_KINDS = {"paragraph", "bullet_list", "numbered_list", "table"}
BRIEF_BLOCK_PURPOSES = {"legal_analysis", "application", "client_fact", "limitation"}
BRIEF_STRUCTURE_PROFILES = {"regulatory-walk-v1"}
BRIEF_SECTION_ROLES = {
    "key_requirements",
    "penalties_enforcement",
    "implementation",
    "other",
}
CANONICAL_BRIEF_SECTIONS = (
    ("key_requirements", "Key Requirements", "requirements"),
    ("penalties_enforcement", "Penalties and Enforcement", "enforcement"),
    ("implementation", "Implementation Workplan", None),
)
SOURCE_FRAMED_LEGAL_LEAD = re.compile(
    r"""
    ^\s*(?:the\s+)?
    (?:(?:one|two|three|four|five|\d+)\s+)?
    (?:
        (?:source|research)\s+packet
        |packet
        |source\s+set
        |materials(?:\s+(?:collected|provided|supplied|retained))?
        |(?:retained|supplied|provided|collected|available)\s+
            (?:(?:official|primary|secondary|eur-lex)\s+)*
            (?:
                materials
                |sources?
                |source\s+set
                |text
                |excerpts?
                |summar(?:y|ies)
                |authorit(?:y|ies)
                |public\s+act
                |statutory\s+compilation
            )
        |(?:official|source)\s+(?:summary|excerpt|materials|packet)
    )\b
    (?:\s+(?:and|or)\s+(?:later\s+)?(?:compilation|materials|sources?|summary))?
    (?=
        \s+
        (?:
            (?:(?:also|separately|expressly|only|merely)\s+)*
            (?:
                establish(?:es|ed|ing)?
                |indicat(?:e|es|ed|ing)
                |show(?:s|ed|ing)?
                |descri(?:be|bes|bed|bing)
                |identif(?:y|ies|ied|ying)
                |stat(?:e|es|ed|ing)
                |provid(?:e|es|ed|ing)
                |reflect(?:s|ed|ing)?
                |record(?:s|ed|ing)?
                |support(?:s|ed|ing)?
                |confirm(?:s|ed|ing)?
                |demonstrat(?:e|es|ed|ing)
                |reproduc(?:e|es|ed|ing)
                |giv(?:e|es|en|ing)
                |contain(?:s|ed|ing)?
                |omit(?:s|ted|ting)?
                |includ(?:e|es|ed|ing)
                |address(?:es|ed|ing)?
                |cover(?:s|ed|ing)?
                |discuss(?:es|ed|ing)?
                |summari(?:ze|zes|zed|zing)
                |set(?:s|ting)?\s+out
                |prohibit(?:s|ed|ing)?
                |require(?:s|d|ing)?
                |permit(?:s|ted|ting)?
                |authoriz(?:e|es|ed|ing)
                |appl(?:y|ies|ied|ying)
                |extend(?:s|ed|ing)?
                |assign(?:s|ed|ing)?
            )
            |(?:does?|did)\s+not\s+
                (?:
                    establish|indicate|show|describe|identify|state|provide
                    |support|confirm|contain|include|address|cover
                )
            |(?:is|are|was|were)\s+(?:not\s+)?(?:an?\s+)?
                (?:sufficient|complete|incomplete|current|clear|unclear|adequate|enough)
        )\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
RENDERER_OWNED_TITLES = {
    "bottom line",
    "evidence and validation appendix",
    "executive summary",
    "limitations and open questions",
    "priority and posture",
    "sources consulted",
}
ISSUE_CATEGORIES = {
    "status",
    "scope",
    "requirements",
    "enforcement",
    "deadlines",
    "implementation",
    "other",
}
PRESENTATION_ROLES = {
    "territorial_scope",
    "covered_entities",
    "covered_activities",
    "exclusions_thresholds",
    "requirement",
    "enforcers",
    "enforcement_mechanisms",
    "penalties_remedies",
    "private_right",
    "cure_rights",
    "defenses",
    "affected_operations",
    "recommended_actions",
    "dependencies",
    "effort",
    "client_facts",
    "related_amendment",
    "related_supersession",
    "related_implementation",
    "related_regime",
}
SOURCE_SECTION_TITLES = {
    "official_primary": "Official and Primary Sources",
    "secondary": "Secondary Sources",
    "commentary_analysis": "Commentary and Analysis",
}
SOURCE_SECTION_ORDER = (
    "Official and Primary Sources",
    "Secondary Sources",
    "Commentary and Analysis",
    "Unclassified Sources",
)
CATEGORY_ORDER = (
    "status",
    "scope",
    "requirements",
    "enforcement",
    "deadlines",
    "implementation",
    "other",
)
REQUIRED_COVERAGE_CATEGORIES = CATEGORY_ORDER[:-1]
_COVERAGE_GAP_MESSAGES = {
    "status": "The retained source set did not establish legal status.",
    "scope": "The retained source set did not establish scope and applicability.",
    "requirements": "The retained source set did not establish legal requirements.",
    "enforcement": "The retained source set did not establish enforcement or remedies.",
    "deadlines": "The retained source set did not establish deadlines or transition timing.",
    "implementation": (
        "The retained source set did not establish implementation implications or the client "
        "facts needed to apply them."
    ),
}
_OFFICIAL_LEGAL_HOSTS = (
    "legislation.gov.uk",
    "eur-lex.europa.eu",
    "fedlex.admin.ch",
)
_PRIMARY_AUTHORITY_TERMS = {
    "act",
    "bill",
    "case",
    "code",
    "constitution",
    "decision",
    "directive",
    "guidance",
    "judgment",
    "law",
    "order",
    "ordinance",
    "regulation",
    "rule",
    "statute",
    "treaty",
}
BLOCKING_REVIEW_CODES = {
    "PROPOSED_QUOTE_AMBIGUOUS",
    "PROPOSED_QUOTE_NOT_FOUND",
    "PROPOSED_SOURCE_MISSING",
}
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
_MARKDOWN_CONTROLS = "\\`*_{}[]()#+!|>"
PROVISION_LEADS_VERSION = "provision-leads-v2"
PROVISION_LEADS_NOTICE = "Heuristic research leads, not legal conclusions."
MAX_PRIORITY_LEADS_PER_TOPIC = 3
COVERAGE_CONTRACT_VERSION = "proposition-coverage-v1"
ATOMIC_COVERAGE_CONTRACT_VERSION = "proposition-coverage-v2"
SOURCE_UNIT_INVENTORY_VERSION = "source-units-v1"
MAX_SOURCE_UNIT_CHARS = 1_600
_SOURCE_UNIT_NONBLANK_BLOCK = re.compile(
    r"\S(?:.*?\S)?(?=\n[ \t]*\n|[ \t\r\n]*\Z)", re.DOTALL
)
_SOURCE_UNIT_ENUMERATOR = re.compile(
    r"^[ \t]*(?:"
    r"\(\s*(?:\d+|[A-Za-z]|[IVXLCDMivxlcdm]+)\s*\)"
    r"|(?:\d+|[A-Za-z]|[IVXLCDMivxlcdm]+)[.)、:\uFF1A]"
    r"|第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*(?:条|條|項|款|節)"
    r"|المادة\s*\(?[0-9\u0660-\u0669]+\)?"
    r")",
    re.MULTILINE,
)
_SOURCE_UNIT_SENTENCE_TERMINATORS = frozenset(".?!;。\uFF01\uFF1F؛।")
_SOURCE_UNIT_HEADING = re.compile(
    r"^[ \t]*(?:"
    r"(?:article|artículo|section|chapter|part|title|schedule|annex)\s+"
    r"[A-Za-z0-9IVXLC.-]+"
    r"|§+\s*[A-Za-z0-9.-]+"
    r"|第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*条"
    r"|المادة\s*\(?[0-9\u0660-\u0669]+\)?"
    r")[^\n]{0,180}$",
    re.IGNORECASE,
)
_PROVISION_HEADING = re.compile(
    r"^\s*(?:(?:article|section|chapter|part|title|schedule|annex)\s+"
    r"[A-Za-z0-9IVXLC.-]+|§+\s*[A-Za-z0-9.-]+|"
    r"第\s*[0-9\uFF10-\uFF19一二三四五六七八九十百千]+\s*条|"
    r"المادة\s*\(?[0-9\u0660-\u0669]+\)?)[^\n]{0,180}$",
    re.IGNORECASE,
)
_PROVISION_BLOCK = re.compile(
    r"\S(?:.*?\S)?(?=\n[ \t]*\n|[ \t\r\n]*\Z)", re.DOTALL
)
_PROVISION_NUMERIC_SIGNAL = re.compile(r"(?:[$€£¥]\s*\d|\b\d[\d,.]*\s*%?\b)")
_PROVISION_BOUNDARY = re.compile(r"(?:[.;!?][ \t]+|\n+)")
_PROVISION_TOPIC_PRIORITY = {
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
_PROVISION_TOPIC_SPECS = (
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

_ATOMIC_DIMENSION_NAMES = (
    "authority_status_timing",
    "actors_scope_activities",
    "definitions_categories",
    "duties_rights_prohibitions",
    "triggers_thresholds",
    "conditions_exceptions_defenses",
    "deadlines_transitions",
    "enforcement_remedies_consequences",
    "cross_references_dependencies",
)
_ATOMIC_ELEMENT_NAMES = (
    "actor",
    "modality",
    "operative_action",
    "object",
    "trigger",
    "threshold",
    "condition",
    "exception",
    "timing",
    "authority",
    "route",
    "consequence",
    "defined_term",
    "defined_meaning",
)
_ATOMIC_REQUIRED_ELEMENTS = {
    "status": ("object",),
    "definition": ("defined_term", "defined_meaning"),
    "scope": ("actor", "object"),
    "duty": ("actor", "modality", "operative_action", "object"),
    "prohibition": ("actor", "modality", "operative_action", "object"),
    "right": ("actor", "modality", "operative_action", "object"),
    "exception": ("exception",),
    "deadline": ("timing",),
    "enforcement_trigger": ("trigger",),
    "enforcement_route": ("authority", "route"),
    "remedy": ("consequence",),
    "penalty": ("consequence",),
    "appeal": ("route",),
    "implementation": ("operative_action", "object"),
    "other": ("object",),
}
_ATOMIC_REQUIRED_RELATIONSHIPS = {
    "exception": ("exception_to",),
    "deadline": ("deadline_for",),
    "enforcement_trigger": ("triggered_by",),
    "enforcement_route": ("enforces",),
    "remedy": ("triggered_by", "consequence_of"),
    "penalty": ("triggered_by", "consequence_of"),
    "appeal": ("appeals_from",),
}
_ATOMIC_ACYCLIC_RELATIONSHIPS = {
    "exception_to",
    "deadline_for",
    "triggered_by",
    "consequence_of",
    "appeals_from",
}


class PortableInputError(ValueError):
    """A portable runner input was unsafe or did not match the public schema."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _PortableDraft(dict[str, Any]):
    """A strictly parsed draft snapshot; plain dict injections remain distinguishable."""


class _PortableUnitReview(dict[str, Any]):
    """A strictly parsed V2 unit-review snapshot."""


class _PortableLeadDisposition(dict[str, Any]):
    """A strictly parsed V2 lead-disposition snapshot."""


class _PortableRuleAtom(dict[str, Any]):
    """A strictly parsed V2 rule-atom snapshot."""


class _PortableRuleRelationship(dict[str, Any]):
    """A strictly parsed V2 rule-relationship snapshot."""


class _PortableGap(dict[str, Any]):
    """A strictly parsed authored-gap snapshot."""


class _PortableIssue(dict[str, Any]):
    """A strictly parsed analysis-issue snapshot."""


class _PortableCitation(dict[str, Any]):
    """A strictly parsed proposed-citation snapshot."""


class _PortableClaim(dict[str, Any]):
    """A strictly parsed analysis-claim snapshot."""


class _PortableFinding(dict[str, Any]):
    """A strictly parsed analysis-finding snapshot."""


class _PortableBrief(dict[str, Any]):
    """A strictly parsed attorney-brief snapshot."""


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise PortableInputError("INVALID_ARGUMENTS", message)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{_sha256(chr(0).join(parts).encode())[:24]}"


def _provision_source_group(source: dict[str, Any], source_id: str) -> str:
    for field in ("canonical_url", "content_hash"):
        value = source.get(field)
        if isinstance(value, str) and value:
            return value
    return source_id


def _provision_priority_score(
    lead: dict[str, Any],
    source: dict[str, Any],
) -> int:
    source_role = source.get("source_role")
    source_quality = source.get("source_quality")
    score = {
        "official_primary": 50,
        "secondary": -10,
        "commentary_analysis": -100,
    }.get(source_role if isinstance(source_role, str) else "", 0)
    score += {
        "primary": 40,
        "secondary": -5,
        "unusable": -100,
    }.get(source_quality if isinstance(source_quality, str) else "", 0)
    score += _PROVISION_TOPIC_PRIORITY.get(str(lead.get("topic")), 0)
    score += 15 if lead.get("heading") is not None else 0
    signals = lead.get("signals")
    score += min(len(signals), 5) if isinstance(signals, list) else 0
    excerpt = lead.get("excerpt")
    if isinstance(excerpt, str) and _PROVISION_NUMERIC_SIGNAL.search(excerpt):
        score += 10
    return score


def _mark_provision_priority_leads(
    leads: list[dict[str, Any]],
    sources: list[dict[str, Any]],
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
                -_provision_priority_score(
                    lead,
                    source_by_id.get(lead["source_id"], {}),
                ),
                lead["source_id"],
                lead["start_char"],
                lead["lead_id"],
            ),
        )
        chosen: list[dict[str, Any]] = []
        used_groups: set[str] = set()
        for lead in ranked:
            source = source_by_id.get(lead["source_id"], {})
            group = _provision_source_group(source, lead["source_id"])
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


def _build_evidence_inventory(sources: list[dict[str, Any]]) -> dict[str, Any]:
    leads: list[dict[str, Any]] = []
    source_count = 0
    for source in sources:
        if source.get("fetch_status") != "succeeded":
            continue
        source_id = source.get("source_id")
        source_text = source.get("normalized_text")
        if (
            not isinstance(source_id, str)
            or not source_id
            or not isinstance(source_text, str)
            or not source_text
        ):
            continue
        source_count += 1
        for block_match in _PROVISION_BLOCK.finditer(source_text):
            block_start, block_end = block_match.span()
            block_text = block_match.group(0)
            first_line = block_text.splitlines()[0].strip()
            heading = first_line if _PROVISION_HEADING.fullmatch(first_line) else None
            for topic, issue_category, patterns in _PROVISION_TOPIC_SPECS:
                matches = [
                    match
                    for pattern in patterns
                    for match in pattern.finditer(block_text)
                ]
                if not matches:
                    continue
                ordered = sorted(
                    {
                        (match.start(), match.end(), match.group(0)): match
                        for match in matches
                    }.values(),
                    key=lambda match: (
                        match.start(),
                        match.end(),
                        match.group(0).casefold(),
                    ),
                )
                absolute = [
                    (block_start + match.start(), block_start + match.end(), match)
                    for match in ordered
                ]
                boundaries = [block_start]
                for index in range(len(absolute) - 1):
                    previous_end = absolute[index][1]
                    next_start = absolute[index + 1][0]
                    separator = _PROVISION_BOUNDARY.search(
                        source_text, previous_end, next_start
                    )
                    boundaries.append(
                        separator.end()
                        if separator is not None
                        else (previous_end + next_start) // 2
                    )
                boundaries.append(block_end)
                for index, (match_start, match_end, match) in enumerate(absolute):
                    partition_start = boundaries[index]
                    partition_end = boundaries[index + 1]
                    if partition_end - partition_start <= 1_600:
                        start, end = partition_start, partition_end
                    else:
                        start = max(partition_start, match_start - 400)
                        end = min(partition_end, match_end + 800)
                    excerpt = source_text[start:end]
                    leads.append(
                        {
                            "lead_id": _stable_id(
                                "lead", source_id, topic, str(start), str(end), excerpt
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
    _mark_provision_priority_leads(leads, sources)
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


def _build_source_unit_inventory(sources: list[dict[str, Any]]) -> dict[str, Any]:
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


def _source_is_eligible(source: dict[str, Any]) -> bool:
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
    for block in _SOURCE_UNIT_NONBLANK_BLOCK.finditer(text):
        block_start, block_end = block.span()
        spans.extend(_partition_source_block(text, block_start, block_end))

    expanded: list[tuple[int, int, str | None, str]] = []
    for start, end, heading in spans:
        for chunk_start, chunk_end in _split_long_source_unit(text, start, end):
            expanded.append(
                (chunk_start, chunk_end, heading, f"chars:{chunk_start}-{chunk_end}")
            )
    _assert_exact_source_unit_partition(text, expanded)
    return expanded


def _partition_source_block(
    text: str,
    block_start: int,
    block_end: int,
) -> list[tuple[int, int, str | None]]:
    heading, body_start = _standalone_source_unit_heading(text, block_start, block_end)
    body_ranges = _split_source_unit_at_enumerators(text, body_start, block_end)
    spans: list[tuple[int, int, str | None]] = []
    for range_start, range_end in body_ranges:
        spans.extend(
            (start, end, heading)
            for start, end in _split_source_unit_clauses(text, range_start, range_end)
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


def _standalone_source_unit_heading(
    text: str, start: int, end: int
) -> tuple[str | None, int]:
    newline = text.find("\n", start, end)
    if newline == -1:
        return None, start
    first_line = text[start:newline].strip()
    if not first_line or not _SOURCE_UNIT_HEADING.fullmatch(first_line):
        return None, start
    body_start = newline + 1
    while body_start < end and text[body_start].isspace():
        body_start += 1
    return first_line, body_start


def _split_source_unit_at_enumerators(text: str, start: int, end: int) -> list[tuple[int, int]]:
    starts = [start]
    for match in _SOURCE_UNIT_ENUMERATOR.finditer(text, start, end):
        if match.start() > start:
            starts.append(match.start())
    return [
        (range_start, range_end)
        for range_start, range_end in zip(starts, [*starts[1:], end], strict=True)
    ]


def _split_source_unit_clauses(text: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    current_start = start
    for index in range(start, end):
        if text[index] in _SOURCE_UNIT_SENTENCE_TERMINATORS:
            spans.append((current_start, index + 1))
            current_start = index + 1
    if current_start < end:
        spans.append((current_start, end))
    return [span for span in spans if any(not char.isspace() for char in text[span[0] : span[1]])]


def _split_long_source_unit(text: str, start: int, end: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    current_start = start
    while end - current_start > MAX_SOURCE_UNIT_CHARS:
        limit = current_start + MAX_SOURCE_UNIT_CHARS
        split_at = _last_source_unit_boundary(text, current_start, limit)
        if split_at is None:
            split_at = _next_source_unit_boundary(text, limit, end)
        if split_at is None:
            split_at = end
        spans.append((current_start, split_at))
        current_start = split_at
    if current_start < end:
        spans.append((current_start, end))
    return spans


def _last_source_unit_boundary(text: str, start: int, limit: int) -> int | None:
    for index in range(limit - 1, start, -1):
        if _is_source_unit_boundary(text[index]):
            return index + 1
    return None


def _next_source_unit_boundary(text: str, start: int, end: int) -> int | None:
    for index in range(start, end):
        if _is_source_unit_boundary(text[index]):
            return index + 1
    return None


def _is_source_unit_boundary(character: str) -> bool:
    return character.isspace() or unicodedata.category(character).startswith("P")


def _assert_exact_source_unit_partition(
    text: str,
    spans: list[tuple[int, int, str | None, str]],
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


def _write_error(code: str, message: str) -> None:
    sys_stderr = __import__("sys").stderr
    sys_stderr.write(json.dumps({"code": code, "message": message}, sort_keys=True) + "\n")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, value: object) -> None:
    _atomic_write(path, _canonical_bytes(value) + b"\n")


def _read_json(path: Path, code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PortableInputError(code, "The input could not be read as UTF-8 JSON.") from None


def _require_object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PortableInputError("INVALID_INPUT", f"{path} must be an object")
    return value


def _require_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str],
    path: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        raise PortableInputError("INVALID_INPUT", f"{path}.{missing[0]} is required")
    if unknown:
        raise PortableInputError("INVALID_INPUT", f"{path}.{unknown[0]} is not permitted")


def _nonblank(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PortableInputError("INVALID_INPUT", f"{path} must be a non-blank string")
    return value.strip()


def _optional_text(value: object, path: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PortableInputError("INVALID_INPUT", f"{path} must be a string or null")
    return value


def _optional_nonblank(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _nonblank(value, path)


def _canonical_public_url(value: object, path: str) -> str | None:
    url = _optional_nonblank(value, path)
    if url is None:
        return None
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise PortableInputError("INVALID_INPUT", f"{path} must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise PortableInputError("INVALID_INPUT", f"{path} must not contain credentials")
    if parsed.hostname is None:
        raise PortableInputError("INVALID_INPUT", f"{path} requires a hostname")
    hostname = parsed.hostname.rstrip(".").casefold()
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        if (
            "." not in hostname
            or hostname == "localhost"
            or hostname.endswith((".localhost", ".local", ".internal", ".home.arpa"))
        ):
            raise PortableInputError(
                "INVALID_INPUT", f"{path} must identify a public authority"
            ) from None
        literal = None
    if literal is not None and not literal.is_global:
        raise PortableInputError("INVALID_INPUT", f"{path} must identify a public authority")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _classify_source_quality(
    declared: str,
    *,
    origin: str,
    canonical_url: str | None,
    authority_type: str | None,
) -> str:
    if declared != "unknown":
        return declared
    parsed = urlsplit(canonical_url or origin)
    hostname = parsed.hostname
    if hostname is None or authority_type is None:
        return declared
    normalized_host = hostname.rstrip(".").casefold()
    official = any(
        normalized_host == host or normalized_host.endswith(f".{host}")
        for host in _OFFICIAL_LEGAL_HOSTS
    )
    authority_words = authority_type.casefold().replace("-", " ").split()
    if official and any(word in _PRIMARY_AUTHORITY_TERMS for word in authority_words):
        return "primary"
    return declared


def _string_list(value: object, path: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a nonempty" if nonempty else "a"
        raise PortableInputError("INVALID_INPUT", f"{path} must be {qualifier} list")
    result = [_nonblank(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return result


def _source_input(value: object, path: str) -> dict[str, Any]:
    source = _require_object(value, path)
    optional = {
        "canonical_url",
        "title",
        "publisher",
        "jurisdiction",
        "authority_type",
        "citation",
        "effective_date",
        "supersession",
        "language",
        "source_quality",
        "source_role",
        "license_assertion",
    }
    _require_keys(source, required={"location"}, optional=optional, path=path)
    quality = source.get("source_quality", "unknown")
    if quality not in SOURCE_QUALITIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.source_quality is invalid")
    source_role = source.get("source_role")
    if source_role is not None and source_role not in SOURCE_ROLES:
        raise PortableInputError("INVALID_INPUT", f"{path}.source_role is invalid")
    return {
        "location": _nonblank(source["location"], f"{path}.location"),
        "canonical_url": _canonical_public_url(
            source.get("canonical_url"), f"{path}.canonical_url"
        ),
        "title": _optional_text(source.get("title"), f"{path}.title"),
        "publisher": _optional_text(source.get("publisher"), f"{path}.publisher"),
        "jurisdiction": _optional_text(source.get("jurisdiction"), f"{path}.jurisdiction"),
        "authority_type": _optional_text(source.get("authority_type"), f"{path}.authority_type"),
        "citation": _optional_text(source.get("citation"), f"{path}.citation"),
        "effective_date": _optional_text(source.get("effective_date"), f"{path}.effective_date"),
        "supersession": _optional_text(source.get("supersession"), f"{path}.supersession"),
        "language": _optional_nonblank(source.get("language"), f"{path}.language"),
        "source_quality": quality,
        "source_role": source_role,
        "license_assertion": _nonblank(
            source.get("license_assertion", "unknown"), f"{path}.license_assertion"
        ),
    }


def _charter(value: object) -> dict[str, Any]:
    charter = _require_object(value, "charter")
    _require_keys(
        charter,
        required={
            "schema_version",
            "matter_id",
            "matter_title",
            "question",
            "jurisdictions",
            "as_of",
            "source_mode",
            "sources",
        },
        optional={"context", "excluded_topics", "output_instructions"},
        path="charter",
    )
    if charter["schema_version"] != "1.0":
        raise PortableInputError("INVALID_INPUT", "charter.schema_version must be 1.0")
    matter_id = _nonblank(charter["matter_id"], "charter.matter_id")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if (
        matter_id in {".", ".."}
        or len(matter_id) > 80
        or matter_id[0] in ".-_"
        or any(character not in allowed for character in matter_id)
    ):
        raise PortableInputError(
            "INVALID_INPUT",
            "charter.matter_id must be one safe path component of at most 80 characters",
        )
    jurisdictions = _string_list(charter["jurisdictions"], "charter.jurisdictions", nonempty=True)
    if len({item.casefold() for item in jurisdictions}) != len(jurisdictions):
        raise PortableInputError("INVALID_INPUT", "charter.jurisdictions must be unique")
    as_of = _nonblank(charter["as_of"], "charter.as_of")
    try:
        date.fromisoformat(as_of)
    except ValueError:
        raise PortableInputError("INVALID_INPUT", "charter.as_of must be an ISO date") from None
    source_mode = charter["source_mode"]
    if source_mode not in {"provided-only", "web"}:
        raise PortableInputError("INVALID_INPUT", "charter.source_mode is invalid")
    raw_sources = charter["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise PortableInputError("INVALID_INPUT", "charter.sources must be a nonempty list")
    return {
        "schema_version": "1.0",
        "matter_id": matter_id,
        "question": _nonblank(charter["question"], "charter.question"),
        "matter_title": _nonblank(charter["matter_title"], "charter.matter_title"),
        "jurisdictions": jurisdictions,
        "as_of": as_of,
        "source_mode": source_mode,
        "context": _optional_text(charter.get("context"), "charter.context"),
        "excluded_topics": _string_list(
            charter.get("excluded_topics", []), "charter.excluded_topics"
        ),
        "output_instructions": _optional_text(
            charter.get("output_instructions"), "charter.output_instructions"
        ),
        "sources": [
            _source_input(source, f"charter.sources[{index}]")
            for index, source in enumerate(raw_sources)
        ],
    }


def _unsafe_managed_path(matter: Path, relative_paths: tuple[Path, ...]) -> Path | None:
    for relative_path in relative_paths:
        candidate = matter / relative_path
        if candidate.is_symlink():
            return candidate
        if not candidate.exists():
            continue
        if not candidate.is_dir():
            return candidate
        try:
            candidate.resolve(strict=True).relative_to(matter)
        except (OSError, ValueError):
            return candidate
    return None


def _matter_path(value: str, *, must_exist: bool = False) -> Path:
    path = Path(value).expanduser().resolve(strict=False)
    if path.exists() and not path.is_dir():
        raise PortableInputError("INVALID_MATTER", "The selected matter path is not a directory.")
    if must_exist and not path.is_dir():
        raise PortableInputError("INVALID_MATTER", "The selected matter directory does not exist.")
    return path


def _validate_layout(matter: Path, run_id: str | None = None) -> None:
    managed = [Path("inputs"), Path("runs"), Path(".regulatory-harvest")]
    if run_id is not None:
        managed.append(Path("runs") / run_id)
    if _unsafe_managed_path(matter, tuple(managed)) is not None:
        raise PortableInputError(
            "INVALID_MATTER",
            "A managed matter path is a symlink, non-directory, or escapes the matter.",
        )


def _copy_atomic(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as source_stream, os.fdopen(descriptor, "wb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _stage_sources(
    sources: list[dict[str, Any]], *, charter_dir: Path, matter: Path
) -> list[dict[str, Any]]:
    staged: list[dict[str, Any]] = []
    for index, source in enumerate(sources, start=1):
        location = source["location"]
        parsed = urlsplit(location)
        windows_absolute = PureWindowsPath(location).is_absolute()
        if not windows_absolute and parsed.scheme in {"http", "https"}:
            staged.append(source)
            continue
        if not windows_absolute and parsed.scheme:
            raise PortableInputError(
                "INVALID_SOURCE",
                "Source locations must be local files or public HTTP(S) URLs.",
            )
        source_path = Path(location).expanduser()
        if not source_path.is_absolute():
            source_path = charter_dir / source_path
        try:
            source_path = source_path.resolve(strict=True)
        except OSError:
            raise PortableInputError(
                "SOURCE_NOT_FOUND", f"A local source was not found: {Path(location).name}"
            ) from None
        if not source_path.is_file():
            raise PortableInputError(
                "INVALID_SOURCE", f"A local source is not a regular file: {source_path.name}"
            )
        suffix = source_path.suffix.lower()
        target = matter / "inputs" / f"{index:03d}-{source_path.stem[:60]}{suffix}"
        if target.is_symlink():
            raise PortableInputError(
                "INVALID_MATTER", "A managed input path must not be a symbolic link."
            )
        _copy_atomic(source_path, target)
        copied = dict(source)
        copied["location"] = target.relative_to(matter).as_posix()
        staged.append(copied)
    return staged


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


class _TextHTMLParser(HTMLParser):
    _ignored: ClassVar[set[str]] = {"script", "style", "noscript", "template"}
    _blocks: ClassVar[set[str]] = {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "nav",
        "p",
        "section",
        "table",
        "td",
        "th",
        "tr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in self._ignored:
            self.ignored_depth += 1
        elif not self.ignored_depth and tag in self._blocks:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._ignored and self.ignored_depth:
            self.ignored_depth -= 1
        elif not self.ignored_depth and tag in self._blocks:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)


def _normalize_content(data: bytes, media_type: str) -> tuple[str, str, list[str]]:
    normalized_media_type = media_type.partition(";")[0].strip().lower()
    if normalized_media_type in {"text/plain", "text/markdown"}:
        try:
            decoded = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("text source is not valid UTF-8") from None
        return _normalize_text(decoded), normalized_media_type, []
    if normalized_media_type in {"text/html", "application/xhtml+xml"}:
        try:
            decoded = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("HTML source is not valid UTF-8") from None
        parser = _TextHTMLParser()
        parser.feed(decoded)
        lines = [line.strip() for line in "".join(parser.parts).splitlines() if line.strip()]
        return _normalize_text("\n".join(lines)), "text/html", []
    if normalized_media_type == "application/pdf":
        raise ValueError(
            "portable runtime requires a verified UTF-8 text extraction for PDF sources"
        )
    raise ValueError(f"unsupported media type: {normalized_media_type or 'unknown'}")


def _validate_public_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("source URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source URL must not contain credentials")
    if parsed.hostname is None:
        raise ValueError("source URL requires a hostname")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise ValueError("source URL has an invalid port") from None
    try:
        literal = ipaddress.ip_address(parsed.hostname)
        addresses = {literal}
    except ValueError:
        try:
            results = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("source hostname could not be resolved") from None
        addresses = {ipaddress.ip_address(result[4][0]) for result in results}
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("source hostname resolves to a non-public address")
    return url


class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        _validate_public_url(urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> tuple[bytes, str, str]:
    _validate_public_url(url)
    opener = build_opener(_SafeRedirectHandler())
    request = Request(url, headers={"User-Agent": "regulatory-harvest/0.1"})
    with opener.open(request, timeout=20) as response:
        final_url = response.geturl()
        _validate_public_url(final_url)
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > MAX_SOURCE_BYTES:
                    raise ValueError("source exceeded the configured byte limit")
            except ValueError as error:
                if "exceeded" in str(error):
                    raise
        data = response.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("source exceeded the configured byte limit")
        media_type = response.headers.get("Content-Type", "application/octet-stream")
        return data, media_type, final_url


def _fetch_source(source: dict[str, Any], *, matter: Path) -> dict[str, Any]:
    origin = source["location"]
    retrieved_at = _now()
    try:
        parsed = urlsplit(origin)
        if parsed.scheme in {"http", "https"}:
            data, media_type, final_origin = _download(origin)
            display_name = source["title"] or parsed.hostname or origin
        elif parsed.scheme:
            raise ValueError("source location uses an unsupported URL scheme")
        else:
            read_path = Path(origin)
            if not read_path.is_absolute():
                read_path = matter / read_path
            data = read_path.read_bytes()
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("source exceeded the configured byte limit")
            local_media_type = {
                ".htm": "text/html",
                ".html": "text/html",
                ".md": "text/markdown",
                ".pdf": "application/pdf",
                ".txt": "text/plain",
            }.get(read_path.suffix.lower())
            media_type = local_media_type or (
                mimetypes.guess_type(read_path.name)[0] or "application/octet-stream"
            )
            final_origin = origin
            display_name = source["title"] or read_path.name
        normalized_text, normalized_media_type, warnings = _normalize_content(data, media_type)
        if not normalized_text.strip():
            raise ValueError("source contained no extractable text")
        content_hash = _sha256(normalized_text.encode("utf-8"))
        source_id = _stable_id("src", final_origin, content_hash)
        return {
            "source_id": source_id,
            "origin": final_origin,
            "display_name": display_name,
            "retrieved_at": retrieved_at,
            "content_hash": content_hash,
            "media_type": normalized_media_type,
            "normalized_text": normalized_text,
            "normalization_warnings": warnings,
            "canonical_url": source["canonical_url"],
            "title": source["title"],
            "publisher": source["publisher"],
            "jurisdiction": source["jurisdiction"],
            "authority_type": source["authority_type"],
            "citation": source["citation"],
            "effective_date": source["effective_date"],
            "supersession": source["supersession"],
            "language": source["language"],
            "license_assertion": source["license_assertion"],
            "source_quality": _classify_source_quality(
                source["source_quality"],
                origin=final_origin,
                canonical_url=source["canonical_url"],
                authority_type=source["authority_type"],
            ),
            "source_role": source["source_role"],
            "fetch_status": "succeeded",
            "error": None,
            "external_ids": {},
        }
    except Exception as error:
        category = "source_error"
        retryable = False
        if isinstance(error, (HTTPError, URLError, TimeoutError)):
            category = "network_error"
            retryable = True
        elif isinstance(error, OSError):
            category = "file_error"
        elif isinstance(error, ValueError):
            category = "normalization_error"
        display_name = source["title"] or Path(urlsplit(origin).path).name or origin
        return {
            "source_id": f"src_{_sha256(origin.encode())[:24]}",
            "origin": origin,
            "display_name": display_name,
            "retrieved_at": retrieved_at,
            "content_hash": None,
            "media_type": "application/octet-stream",
            "normalized_text": "",
            "normalization_warnings": [],
            "canonical_url": source["canonical_url"],
            "title": source["title"],
            "publisher": source["publisher"],
            "jurisdiction": source["jurisdiction"],
            "authority_type": source["authority_type"],
            "citation": source["citation"],
            "effective_date": source["effective_date"],
            "supersession": source["supersession"],
            "language": source["language"],
            "license_assertion": source["license_assertion"],
            "source_quality": "unusable",
            "source_role": source["source_role"],
            "fetch_status": "failed",
            "error": {
                "category": category,
                "retryable": retryable,
                "message": str(error) or type(error).__name__,
                "provider_status_code": getattr(error, "code", None)
                if isinstance(error, HTTPError)
                else None,
            },
            "external_ids": {},
        }


def _request_from_charter(charter: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "request_id": charter["matter_id"],
        "question": charter["question"],
        "matter_title": charter["matter_title"],
        "jurisdictions": charter["jurisdictions"],
        "as_of": charter["as_of"],
        "source_mode": charter["source_mode"],
        "source_inputs": sources,
        "context": charter["context"],
        "excluded_topics": charter["excluded_topics"],
        "output_instructions": charter["output_instructions"],
    }


def _gap(
    code: str,
    message: str,
    jurisdiction: str | None,
    source_ids: list[str],
    category: str = "other",
    presentation_role: str | None = None,
) -> dict[str, Any]:
    return {
        "gap_id": _stable_id(
            "gap", code, message, category, presentation_role or "", jurisdiction or "", *source_ids
        ),
        "code": code,
        "message": message,
        "category": category,
        "presentation_role": presentation_role,
        "jurisdiction": jurisdiction,
        "source_ids": source_ids,
    }


def prepare(charter_path: Path, matter: Path) -> dict[str, object]:
    charter_path = charter_path.expanduser().resolve(strict=True)
    try:
        charter = _charter(_read_json(charter_path, "INVALID_CHARTER"))
    except PortableInputError as error:
        if error.code == "INVALID_INPUT":
            raise PortableInputError("INVALID_CHARTER", str(error)) from None
        raise
    matter.mkdir(parents=True, exist_ok=True)
    _validate_layout(matter, charter["matter_id"])
    staged = _stage_sources(charter["sources"], charter_dir=charter_path.parent, matter=matter)
    request = _request_from_charter(charter, staged)
    source_records = [_fetch_source(source, matter=matter) for source in staged]
    evidence_inventory = _build_evidence_inventory(source_records)
    source_unit_inventory = _build_source_unit_inventory(source_records)
    gaps = [
        _gap(
            "MODEL_PROVIDER_NOT_CONFIGURED",
            "No model provider was configured; analysis stages were skipped.",
            jurisdiction,
            [],
        )
        for jurisdiction in request["jurisdictions"]
    ]
    gaps.extend(
        _gap(
            "SOURCE_RETRIEVAL_FAILED",
            "A requested source could not be retrieved or normalized.",
            source["jurisdiction"],
            [source["source_id"]],
        )
        for source in source_records
        if source["fetch_status"] == "failed"
    )
    dossier = {
        "schema_version": "1.0",
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "source_mode": request["source_mode"],
        "request": request,
        "sources": source_records,
        "gaps": gaps,
        "evidence_inventory": evidence_inventory,
        "source_unit_inventory": source_unit_inventory,
    }
    dossier_path = matter / "agent-dossier.json"
    _write_json(matter / "research-charter.json", charter)
    _write_json(matter / "request.json", request)
    _write_json(dossier_path, dossier)
    succeeded = sum(source["fetch_status"] == "succeeded" for source in source_records)
    failed = len(source_records) - succeeded
    if not succeeded:
        raise PortableInputError(
            "NO_USABLE_SOURCES",
            "No source was retrieved successfully; inspect the dossier and revise the source set.",
        )
    return {
        "dossier": str(dossier_path),
        "matter": str(matter),
        "request": str(matter / "request.json"),
        "source_counts": {"failed": failed, "succeeded": succeeded},
        "evidence_lead_counts": evidence_inventory["topic_counts"],
        "priority_evidence_lead_counts": evidence_inventory[
            "priority_topic_counts"
        ],
        "source_unit_count": source_unit_inventory["unit_count"],
        "status": "prepared",
    }


def _unique_strings(value: object, path: str) -> list[str]:
    values = _string_list(value, path)
    if len(set(values)) != len(values):
        raise PortableInputError("INVALID_INPUT", f"{path} identifiers must be unique")
    return values


def _visible_atomic_bindings(value: dict[str, Any], path: str) -> dict[str, list[str]]:
    bindings: dict[str, list[str]] = {}
    for field_name in ("atom_ids", "relationship_ids"):
        identifiers = sorted(
            _unique_strings(value.get(field_name, []), f"{path}.{field_name}")
        )
        if identifiers:
            bindings[field_name] = identifiers
    return bindings


def _brief_item(value: object, path: str) -> dict[str, Any]:
    item = _require_object(value, path)
    _require_keys(
        item,
        required={"text"},
        optional={
            "finding_ids",
            "claim_ids",
            "enforcement_trigger_claim_ids",
            "enforcement_consequence_claim_ids",
            "atom_ids",
            "relationship_ids",
        },
        path=path,
    )
    return {
        "text": _nonblank(item["text"], f"{path}.text"),
        "finding_ids": _unique_strings(item.get("finding_ids", []), f"{path}.finding_ids"),
        "claim_ids": _unique_strings(item.get("claim_ids", []), f"{path}.claim_ids"),
        "enforcement_trigger_claim_ids": _unique_strings(
            item.get("enforcement_trigger_claim_ids", []),
            f"{path}.enforcement_trigger_claim_ids",
        ),
        "enforcement_consequence_claim_ids": _unique_strings(
            item.get("enforcement_consequence_claim_ids", []),
            f"{path}.enforcement_consequence_claim_ids",
        ),
        **_visible_atomic_bindings(item, path),
    }


def _brief_table_row(value: object, path: str) -> dict[str, Any]:
    row = _require_object(value, path)
    _require_keys(
        row,
        required={"cells"},
        optional={
            "finding_ids",
            "claim_ids",
            "enforcement_trigger_claim_ids",
            "enforcement_consequence_claim_ids",
            "atom_ids",
            "relationship_ids",
        },
        path=path,
    )
    return {
        "cells": _string_list(row["cells"], f"{path}.cells", nonempty=True),
        "finding_ids": _unique_strings(row.get("finding_ids", []), f"{path}.finding_ids"),
        "claim_ids": _unique_strings(row.get("claim_ids", []), f"{path}.claim_ids"),
        "enforcement_trigger_claim_ids": _unique_strings(
            row.get("enforcement_trigger_claim_ids", []),
            f"{path}.enforcement_trigger_claim_ids",
        ),
        "enforcement_consequence_claim_ids": _unique_strings(
            row.get("enforcement_consequence_claim_ids", []),
            f"{path}.enforcement_consequence_claim_ids",
        ),
        **_visible_atomic_bindings(row, path),
    }


def _brief_block(value: object, path: str) -> dict[str, Any]:
    block = _require_object(value, path)
    _require_keys(
        block,
        required={"kind", "purpose"},
        optional={
            "text",
            "finding_ids",
            "claim_ids",
            "enforcement_trigger_claim_ids",
            "enforcement_consequence_claim_ids",
            "atom_ids",
            "relationship_ids",
            "items",
            "columns",
            "rows",
        },
        path=path,
    )
    kind = block["kind"]
    purpose = block["purpose"]
    if kind not in BRIEF_BLOCK_KINDS:
        raise PortableInputError("INVALID_INPUT", f"{path}.kind is invalid")
    if purpose not in BRIEF_BLOCK_PURPOSES:
        raise PortableInputError("INVALID_INPUT", f"{path}.purpose is invalid")
    raw_items = block.get("items", [])
    raw_rows = block.get("rows", [])
    if not isinstance(raw_items, list):
        raise PortableInputError("INVALID_INPUT", f"{path}.items must be a list")
    if not isinstance(raw_rows, list):
        raise PortableInputError("INVALID_INPUT", f"{path}.rows must be a list")
    text_value = _optional_nonblank(block.get("text"), f"{path}.text")
    finding_ids = _unique_strings(block.get("finding_ids", []), f"{path}.finding_ids")
    claim_ids = _unique_strings(block.get("claim_ids", []), f"{path}.claim_ids")
    trigger_ids = _unique_strings(
        block.get("enforcement_trigger_claim_ids", []),
        f"{path}.enforcement_trigger_claim_ids",
    )
    consequence_ids = _unique_strings(
        block.get("enforcement_consequence_claim_ids", []),
        f"{path}.enforcement_consequence_claim_ids",
    )
    atomic_bindings = _visible_atomic_bindings(block, path)
    items = [
        _brief_item(item, f"{path}.items[{index}]")
        for index, item in enumerate(raw_items)
    ]
    columns = _string_list(block.get("columns", []), f"{path}.columns")
    rows = [
        _brief_table_row(row, f"{path}.rows[{index}]")
        for index, row in enumerate(raw_rows)
    ]
    if kind == "paragraph":
        if text_value is None or items or columns or rows:
            raise PortableInputError(
                "INVALID_INPUT", f"{path} paragraph blocks require only text"
            )
    elif kind in {"bullet_list", "numbered_list"}:
        if (
            text_value is not None
            or not items
            or columns
            or rows
            or finding_ids
            or claim_ids
            or trigger_ids
            or consequence_ids
            or atomic_bindings
        ):
            raise PortableInputError(
                "INVALID_INPUT",
                f"{path} list blocks require only items with item-level evidence",
            )
    elif (
        text_value is not None
        or items
        or len(columns) < 2
        or not rows
        or finding_ids
        or claim_ids
        or trigger_ids
        or consequence_ids
        or atomic_bindings
        or any(len(row["cells"]) != len(columns) for row in rows)
    ):
        raise PortableInputError(
            "INVALID_INPUT",
            f"{path} table blocks require matching columns and rows with row-level evidence",
        )
    return {
        "kind": kind,
        "purpose": purpose,
        "text": text_value,
        "finding_ids": finding_ids,
        "claim_ids": claim_ids,
        "enforcement_trigger_claim_ids": trigger_ids,
        "enforcement_consequence_claim_ids": consequence_ids,
        **atomic_bindings,
        "items": items,
        "columns": columns,
        "rows": rows,
    }


def _brief_title(value: object, path: str) -> str:
    title = _nonblank(value, path)
    if title.casefold() in RENDERER_OWNED_TITLES:
        raise PortableInputError(
            "INVALID_INPUT", f"{path} is owned by the deterministic report renderer"
        )
    return title


def _brief_subsection(value: object, path: str) -> dict[str, Any]:
    subsection = _require_object(value, path)
    _require_keys(
        subsection,
        required={"subsection_id", "title", "blocks"},
        optional=set(),
        path=path,
    )
    raw_blocks = subsection["blocks"]
    if not isinstance(raw_blocks, list) or not raw_blocks:
        raise PortableInputError("INVALID_INPUT", f"{path}.blocks must be a nonempty list")
    return {
        "subsection_id": _nonblank(subsection["subsection_id"], f"{path}.subsection_id"),
        "title": _brief_title(subsection["title"], f"{path}.title"),
        "blocks": [
            _brief_block(block, f"{path}.blocks[{index}]")
            for index, block in enumerate(raw_blocks)
        ],
    }


def _brief_section(value: object, path: str) -> dict[str, Any]:
    section = _require_object(value, path)
    _require_keys(
        section,
        required={"section_id", "title"},
        optional={"blocks", "role", "subsections"},
        path=path,
    )
    role = section.get("role")
    if role is not None and role not in BRIEF_SECTION_ROLES:
        raise PortableInputError("INVALID_INPUT", f"{path}.role is invalid")
    raw_blocks = section.get("blocks", [])
    raw_subsections = section.get("subsections", [])
    if not isinstance(raw_blocks, list):
        raise PortableInputError("INVALID_INPUT", f"{path}.blocks must be a list")
    if not isinstance(raw_subsections, list):
        raise PortableInputError("INVALID_INPUT", f"{path}.subsections must be a list")
    if not raw_blocks and not raw_subsections:
        raise PortableInputError(
            "INVALID_INPUT", f"{path} must contain a block or subsection"
        )
    subsections = [
        _brief_subsection(subsection, f"{path}.subsections[{index}]")
        for index, subsection in enumerate(raw_subsections)
    ]
    subsection_ids = [item["subsection_id"] for item in subsections]
    if len(set(subsection_ids)) != len(subsection_ids):
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.subsections identifiers must be unique"
        )
    return {
        "section_id": _nonblank(section["section_id"], f"{path}.section_id"),
        "title": _brief_title(section["title"], f"{path}.title"),
        "role": role,
        "blocks": [
            _brief_block(block, f"{path}.blocks[{index}]")
            for index, block in enumerate(raw_blocks)
        ],
        "subsections": subsections,
    }


def _brief(value: object, path: str) -> dict[str, Any]:
    brief = _require_object(value, path)
    _require_keys(
        brief,
        required={"executive_summary", "sections"},
        optional={"structure_profile"},
        path=path,
    )
    structure_profile = brief.get("structure_profile")
    if (
        structure_profile is not None
        and structure_profile not in BRIEF_STRUCTURE_PROFILES
    ):
        raise PortableInputError("INVALID_INPUT", f"{path}.structure_profile is invalid")
    raw_summary = brief["executive_summary"]
    raw_sections = brief["sections"]
    if not isinstance(raw_summary, list) or not raw_summary:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.executive_summary must be a nonempty list"
        )
    if not isinstance(raw_sections, list) or not raw_sections:
        raise PortableInputError("INVALID_INPUT", f"{path}.sections must be a nonempty list")
    sections = [
        _brief_section(section, f"{path}.sections[{index}]")
        for index, section in enumerate(raw_sections)
    ]
    section_ids = [section["section_id"] for section in sections]
    if len(set(section_ids)) != len(section_ids):
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.sections identifiers must be unique"
        )
    return _PortableBrief({
        "structure_profile": structure_profile,
        "executive_summary": [
            _brief_block(block, f"{path}.executive_summary[{index}]")
            for index, block in enumerate(raw_summary)
        ],
        "sections": sections,
    })


def _coverage_element(value: object, path: str) -> dict[str, str | None]:
    element = _require_object(value, path)
    _require_keys(element, required={"status"}, optional={"text"}, path=path)
    status = element["status"]
    if not isinstance(status, str) or status not in COVERAGE_ELEMENT_STATUSES:
        raise PortableInputError("INVALID_INPUT", f"{path}.status is invalid")
    text = element.get("text")
    if status == "stated":
        if not isinstance(text, str) or not text.strip():
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: stated status requires nonblank text"
            )
        text = text.strip()
    elif text is not None:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: {status} status requires text to be null"
        )
    return {"status": status, "text": text}


_COVERAGE_ELEMENT_FIELDS = (
    "subject",
    "operative_rule",
    "object",
    "trigger_or_threshold",
    "conditions_or_exceptions",
    "timing",
    "consequence_or_remedy",
    "authority_or_route",
)


def _coverage_elements(value: object, path: str) -> dict[str, dict[str, str | None]]:
    elements = _require_object(value, path)
    fields = set(_COVERAGE_ELEMENT_FIELDS)
    _require_keys(elements, required=fields, optional=set(), path=path)
    return {
        field: _coverage_element(elements[field], f"{path}.{field}")
        for field in _COVERAGE_ELEMENT_FIELDS
    }


def _coverage_ids(value: object, path: str) -> list[str]:
    values = _string_list(value, path)
    if len(set(values)) != len(values):
        raise PortableInputError("INVALID_INPUT", f"{path} must be unique")
    return values


def _proposition_coverage_row(value: object, path: str) -> dict[str, Any]:
    row = _require_object(value, path)
    _require_keys(
        row,
        required={"coverage_id", "category", "proposition_type", "disposition"},
        optional={
            "unit_ids",
            "lead_ids",
            "elements",
            "claim_ids",
            "gap_codes",
            "rationale",
        },
        path=path,
    )
    coverage_id = _nonblank(row["coverage_id"], f"{path}.coverage_id")
    unit_ids = _coverage_ids(row.get("unit_ids", []), f"{path}.unit_ids")
    lead_ids = _coverage_ids(row.get("lead_ids", []), f"{path}.lead_ids")
    claim_ids = _coverage_ids(row.get("claim_ids", []), f"{path}.claim_ids")
    gap_codes = _coverage_ids(row.get("gap_codes", []), f"{path}.gap_codes")
    category = row["category"]
    if not isinstance(category, str) or category not in ISSUE_CATEGORIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.category is invalid")
    proposition_type = row["proposition_type"]
    if not isinstance(proposition_type, str) or proposition_type not in PROPOSITION_TYPES:
        raise PortableInputError("INVALID_INPUT", f"{path}.proposition_type is invalid")
    disposition = row["disposition"]
    if not isinstance(disposition, str) or disposition not in COVERAGE_DISPOSITIONS:
        raise PortableInputError("INVALID_INPUT", f"{path}.disposition is invalid")
    raw_elements = row.get("elements")
    elements = (
        None if raw_elements is None else _coverage_elements(raw_elements, f"{path}.elements")
    )
    rationale = _optional_nonblank(row.get("rationale"), f"{path}.rationale")
    if not unit_ids and not lead_ids:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: coverage row requires at least one unit_id or lead_id"
        )

    if disposition == "covered":
        if elements is None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: covered disposition requires elements"
            )
        if not claim_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: covered disposition requires claim_ids"
            )
        if (
            elements["subject"]["status"] != "stated"
            or elements["operative_rule"]["status"] != "stated"
        ):
            raise PortableInputError(
                "INVALID_INPUT",
                f"{path}: covered disposition requires stated subject and operative_rule",
            )
        has_not_established = any(
            elements[field]["status"] == "not_established"
            for field in _COVERAGE_ELEMENT_FIELDS
            if field not in {"subject", "operative_rule"}
        )
        if has_not_established and not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_established elements require gap_codes"
            )
        if not has_not_established and gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap_codes require a not_established element"
            )
    elif disposition == "gap":
        if claim_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition cannot include claim_ids"
            )
        if not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition requires gap_codes"
            )
        if rationale is None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition requires a rationale"
            )
        if elements is not None and any(
            element["status"] == "stated" for element in elements.values()
        ):
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition cannot include stated elements"
            )
    else:
        if elements is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_material disposition cannot include elements"
            )
        if claim_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_material disposition cannot include claim_ids"
            )
        if gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_material disposition cannot include gap_codes"
            )
        if rationale is None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_material disposition requires a rationale"
            )

    return {
        "coverage_id": coverage_id,
        "unit_ids": unit_ids,
        "lead_ids": lead_ids,
        "category": category,
        "proposition_type": proposition_type,
        "disposition": disposition,
        "elements": elements,
        "claim_ids": claim_ids,
        "gap_codes": gap_codes,
        "rationale": rationale,
    }


def _atomic_dimension_review(value: object, path: str) -> dict[str, Any]:
    review = _require_object(value, path)
    _require_keys(
        review,
        required={"disposition"},
        optional={"atom_ids", "gap_codes", "rationale"},
        path=path,
    )
    disposition = review["disposition"]
    if not isinstance(disposition, str) or disposition not in UNIT_DIMENSION_DISPOSITIONS:
        raise PortableInputError("INVALID_INPUT", f"{path}.disposition is invalid")
    atom_ids = _coverage_ids(review.get("atom_ids", []), f"{path}.atom_ids")
    gap_codes = _coverage_ids(review.get("gap_codes", []), f"{path}.gap_codes")
    rationale = _optional_nonblank(review.get("rationale"), f"{path}.rationale")
    if disposition == "mapped":
        if not atom_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: mapped disposition requires atom_ids"
            )
        if gap_codes or rationale is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: mapped disposition permits only atom_ids"
            )
    elif disposition == "gap":
        if not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition requires gap_codes"
            )
        if atom_ids or rationale is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition permits only gap_codes"
            )
    elif disposition == "not_present":
        if atom_ids or gap_codes or rationale is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_present disposition permits no payload"
            )
    elif rationale is None:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: not_material disposition requires a rationale"
        )
    elif atom_ids or gap_codes:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: not_material disposition permits only a rationale"
        )
    return {
        "disposition": disposition,
        "atom_ids": atom_ids,
        "gap_codes": gap_codes,
        "rationale": rationale,
    }


def _atomic_unit_review(value: object, path: str) -> _PortableUnitReview:
    review = _require_object(value, path)
    _require_keys(
        review,
        required={"unit_id", "dimensions"},
        optional=set(),
        path=path,
    )
    dimensions = _require_object(review["dimensions"], f"{path}.dimensions")
    dimension_fields = set(_ATOMIC_DIMENSION_NAMES)
    _require_keys(
        dimensions,
        required=dimension_fields,
        optional=set(),
        path=f"{path}.dimensions",
    )
    return _PortableUnitReview(
        {
            "unit_id": _nonblank(review["unit_id"], f"{path}.unit_id"),
            "dimensions": {
                field_name: _atomic_dimension_review(
                    dimensions[field_name], f"{path}.dimensions.{field_name}"
                )
                for field_name in _ATOMIC_DIMENSION_NAMES
            },
        }
    )


def _atomic_lead_disposition(value: object, path: str) -> _PortableLeadDisposition:
    review = _require_object(value, path)
    _require_keys(
        review,
        required={"lead_id", "disposition"},
        optional={"atom_ids", "gap_codes", "rationale"},
        path=path,
    )
    disposition = review["disposition"]
    if not isinstance(disposition, str) or disposition not in LEAD_DISPOSITIONS_V2:
        raise PortableInputError("INVALID_INPUT", f"{path}.disposition is invalid")
    atom_ids = _coverage_ids(review.get("atom_ids", []), f"{path}.atom_ids")
    gap_codes = _coverage_ids(review.get("gap_codes", []), f"{path}.gap_codes")
    rationale = _optional_nonblank(review.get("rationale"), f"{path}.rationale")
    if disposition == "mapped":
        if not atom_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: mapped disposition requires atom_ids"
            )
        if gap_codes or rationale is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: mapped disposition permits only atom_ids"
            )
    elif disposition == "gap":
        if not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition requires gap_codes"
            )
        if atom_ids or rationale is not None:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: gap disposition permits only gap_codes"
            )
    elif rationale is None:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: not_material disposition requires a rationale"
        )
    elif atom_ids or gap_codes:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: not_material disposition permits only a rationale"
        )
    return _PortableLeadDisposition(
        {
            "lead_id": _nonblank(review["lead_id"], f"{path}.lead_id"),
            "disposition": disposition,
            "atom_ids": atom_ids,
            "gap_codes": gap_codes,
            "rationale": rationale,
        }
    )


def _atomic_element(value: object, path: str) -> dict[str, Any]:
    element = _require_object(value, path)
    _require_keys(
        element,
        required={"status"},
        optional={"text", "claim_ids", "gap_codes"},
        path=path,
    )
    status = element["status"]
    if not isinstance(status, str) or status not in COVERAGE_ELEMENT_STATUSES:
        raise PortableInputError("INVALID_INPUT", f"{path}.status is invalid")
    text = _optional_nonblank(element.get("text"), f"{path}.text")
    claim_ids = _coverage_ids(element.get("claim_ids", []), f"{path}.claim_ids")
    gap_codes = _coverage_ids(element.get("gap_codes", []), f"{path}.gap_codes")
    if status == "stated":
        if text is None:
            raise PortableInputError("INVALID_INPUT", f"{path}: stated element requires text")
        if not claim_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: stated element requires claim_ids"
            )
        if gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: stated element cannot include gap_codes"
            )
    elif status == "not_established":
        if not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_established element requires gap_codes"
            )
        if text is not None or claim_ids:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}: not_established element permits only gap_codes"
            )
    elif text is not None or claim_ids or gap_codes:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: not_applicable element permits no payload"
        )
    return {
        "status": status,
        "text": text,
        "claim_ids": claim_ids,
        "gap_codes": gap_codes,
    }


def _atomic_rule_atom(value: object, path: str) -> _PortableRuleAtom:
    atom = _require_object(value, path)
    _require_keys(
        atom,
        required={
            "atom_id",
            "category",
            "proposition_type",
            "materiality",
            "elements",
            "omission_rationale",
        },
        optional={"unit_ids", "lead_ids"},
        path=path,
    )
    category = atom["category"]
    proposition_type = atom["proposition_type"]
    materiality = atom["materiality"]
    if not isinstance(category, str) or category not in ISSUE_CATEGORIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.category is invalid")
    if not isinstance(proposition_type, str) or proposition_type not in PROPOSITION_TYPES:
        raise PortableInputError("INVALID_INPUT", f"{path}.proposition_type is invalid")
    if not isinstance(materiality, str) or materiality not in ATOM_MATERIALITIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.materiality is invalid")
    unit_ids = _coverage_ids(atom.get("unit_ids", []), f"{path}.unit_ids")
    lead_ids = _coverage_ids(atom.get("lead_ids", []), f"{path}.lead_ids")
    if not unit_ids and not lead_ids:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: atom requires at least one unit_id or lead_id"
        )
    elements = _require_object(atom["elements"], f"{path}.elements")
    element_fields = set(_ATOMIC_ELEMENT_NAMES)
    _require_keys(
        elements,
        required=element_fields,
        optional=set(),
        path=f"{path}.elements",
    )
    return _PortableRuleAtom(
        {
            "atom_id": _nonblank(atom["atom_id"], f"{path}.atom_id"),
            "unit_ids": unit_ids,
            "lead_ids": lead_ids,
            "category": category,
            "proposition_type": proposition_type,
            "materiality": materiality,
            "elements": {
                field_name: _atomic_element(
                    elements[field_name], f"{path}.elements.{field_name}"
                )
                for field_name in _ATOMIC_ELEMENT_NAMES
            },
            "omission_rationale": _nonblank(
                atom["omission_rationale"], f"{path}.omission_rationale"
            ),
        }
    )


def _atomic_rule_relationship(value: object, path: str) -> _PortableRuleRelationship:
    relationship = _require_object(value, path)
    _require_keys(
        relationship,
        required={
            "relationship_id",
            "relation_type",
            "source_atom_id",
            "target_atom_id",
            "claim_ids",
        },
        optional=set(),
        path=path,
    )
    relation_type = relationship["relation_type"]
    if not isinstance(relation_type, str) or relation_type not in ATOM_RELATIONSHIP_TYPES:
        raise PortableInputError("INVALID_INPUT", f"{path}.relation_type is invalid")
    source_atom_id = _nonblank(
        relationship["source_atom_id"], f"{path}.source_atom_id"
    )
    target_atom_id = _nonblank(
        relationship["target_atom_id"], f"{path}.target_atom_id"
    )
    if source_atom_id == target_atom_id:
        raise PortableInputError(
            "INVALID_INPUT", f"{path}: relationship cannot link an atom to itself"
        )
    claim_ids = _coverage_ids(relationship["claim_ids"], f"{path}.claim_ids")
    if not claim_ids:
        raise PortableInputError("INVALID_INPUT", f"{path}.claim_ids must be nonempty")
    return _PortableRuleRelationship(
        {
            "relationship_id": _nonblank(
                relationship["relationship_id"], f"{path}.relationship_id"
            ),
            "relation_type": relation_type,
            "source_atom_id": source_atom_id,
            "target_atom_id": target_atom_id,
            "claim_ids": claim_ids,
        }
    )


def _draft_issue(value: object, path: str) -> _PortableIssue:
    issue = _require_object(value, path)
    _require_keys(
        issue,
        required={"issue_id", "title"},
        optional={"category", "description", "jurisdictions", "presentation_role"},
        path=path,
    )
    category = issue.get("category", "other")
    if category not in ISSUE_CATEGORIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.category is invalid")
    presentation_role = issue.get("presentation_role")
    if presentation_role is not None and presentation_role not in PRESENTATION_ROLES:
        raise PortableInputError("INVALID_INPUT", f"{path}.presentation_role is invalid")
    return _PortableIssue(
        {
            "issue_id": _nonblank(issue["issue_id"], f"{path}.issue_id"),
            "title": _nonblank(issue["title"], f"{path}.title"),
            "category": category,
            "presentation_role": presentation_role,
            "description": _optional_text(issue.get("description"), f"{path}.description"),
            "jurisdictions": _string_list(
                issue.get("jurisdictions", []), f"{path}.jurisdictions"
            ),
        }
    )


def _draft_citation(value: object, path: str) -> _PortableCitation:
    citation = _require_object(value, path)
    _require_keys(
        citation,
        required={"source_id", "quote"},
        optional={"occurrence"},
        path=path,
    )
    occurrence = citation.get("occurrence")
    if occurrence is not None and (
        not isinstance(occurrence, int)
        or isinstance(occurrence, bool)
        or occurrence < 1
    ):
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.occurrence must be positive"
        )
    return _PortableCitation(
        {
            "source_id": _nonblank(citation["source_id"], f"{path}.source_id"),
            "quote": _nonblank(citation["quote"], f"{path}.quote"),
            "occurrence": occurrence,
        }
    )


def _draft_claim(value: object, path: str) -> _PortableClaim:
    claim = _require_object(value, path)
    _require_keys(
        claim,
        required={"claim_id", "text", "kind"},
        optional={"confidence", "enforcement_roles", "proposed_citations"},
        path=path,
    )
    kind = claim["kind"]
    if kind not in CLAIM_KINDS:
        raise PortableInputError("INVALID_INPUT", f"{path}.kind is invalid")
    confidence = claim.get("confidence")
    if confidence is not None and (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= float(confidence) <= 1
    ):
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.confidence must be between 0 and 1"
        )
    enforcement_roles = _unique_strings(
        claim.get("enforcement_roles", []), f"{path}.enforcement_roles"
    )
    if not set(enforcement_roles) <= ENFORCEMENT_CLAIM_ROLES:
        raise PortableInputError("INVALID_INPUT", f"{path}.enforcement_roles is invalid")
    raw_citations = claim.get("proposed_citations", [])
    if not isinstance(raw_citations, list):
        raise PortableInputError(
            "INVALID_INPUT", f"{path}.proposed_citations must be a list"
        )
    return _PortableClaim(
        {
            "claim_id": _nonblank(claim["claim_id"], f"{path}.claim_id"),
            "text": _nonblank(claim["text"], f"{path}.text"),
            "kind": kind,
            "enforcement_roles": enforcement_roles,
            "confidence": None if confidence is None else float(confidence),
            "proposed_citations": [
                _draft_citation(raw, f"{path}.proposed_citations[{index}]")
                for index, raw in enumerate(raw_citations)
            ],
        }
    )


def _draft_finding(value: object, path: str) -> _PortableFinding:
    finding = _require_object(value, path)
    _require_keys(
        finding,
        required={
            "finding_id",
            "issue_id",
            "title",
            "jurisdiction",
            "authority",
            "severity",
            "practical_implication",
        },
        optional={"claims"},
        path=path,
    )
    severity = finding["severity"]
    if severity not in SEVERITIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.severity is invalid")
    raw_claims = finding.get("claims", [])
    if not isinstance(raw_claims, list):
        raise PortableInputError("INVALID_INPUT", f"{path}.claims must be a list")
    return _PortableFinding(
        {
            "finding_id": _nonblank(finding["finding_id"], f"{path}.finding_id"),
            "issue_id": _nonblank(finding["issue_id"], f"{path}.issue_id"),
            "title": _nonblank(finding["title"], f"{path}.title"),
            "jurisdiction": _nonblank(
                finding["jurisdiction"], f"{path}.jurisdiction"
            ),
            "authority": _nonblank(finding["authority"], f"{path}.authority"),
            "severity": severity,
            "practical_implication": _nonblank(
                finding["practical_implication"], f"{path}.practical_implication"
            ),
            "claims": [
                _draft_claim(raw, f"{path}.claims[{index}]")
                for index, raw in enumerate(raw_claims)
            ],
        }
    )


def _draft_gap(value: object, path: str) -> _PortableGap:
    gap = _require_object(value, path)
    _require_keys(
        gap,
        required={"code", "message"},
        optional={"category", "jurisdiction", "presentation_role", "source_ids"},
        path=path,
    )
    category = gap.get("category", "other")
    if category not in ISSUE_CATEGORIES:
        raise PortableInputError("INVALID_INPUT", f"{path}.category is invalid")
    presentation_role = gap.get("presentation_role")
    if presentation_role is not None and presentation_role not in PRESENTATION_ROLES:
        raise PortableInputError("INVALID_INPUT", f"{path}.presentation_role is invalid")
    return _PortableGap(
        {
            "code": _nonblank(gap["code"], f"{path}.code"),
            "message": _nonblank(gap["message"], f"{path}.message"),
            "category": category,
            "presentation_role": presentation_role,
            "jurisdiction": _optional_text(
                gap.get("jurisdiction"), f"{path}.jurisdiction"
            ),
            "source_ids": _string_list(
                gap.get("source_ids", []), f"{path}.source_ids"
            ),
        }
    )


def _draft(value: object) -> dict[str, Any]:
    draft = _require_object(value, "draft")
    _require_keys(
        draft,
        required={"issues", "findings"},
        optional={
            "brief",
            "gaps",
            "lead_reviews",
            "coverage_contract_version",
            "proposition_coverage",
            "unit_reviews",
            "lead_dispositions_v2",
            "rule_atoms",
            "rule_relationships",
        },
        path="draft",
    )
    if not isinstance(draft["issues"], list) or not isinstance(draft["findings"], list):
        raise PortableInputError("INVALID_INPUT", "draft issues and findings must be lists")
    if not isinstance(draft.get("gaps", []), list):
        raise PortableInputError("INVALID_INPUT", "draft.gaps must be a list")
    if not isinstance(draft.get("lead_reviews", []), list):
        raise PortableInputError("INVALID_INPUT", "draft.lead_reviews must be a list")
    if not isinstance(draft.get("proposition_coverage", []), list):
        raise PortableInputError("INVALID_INPUT", "draft.proposition_coverage must be a list")
    for field_name in (
        "unit_reviews",
        "lead_dispositions_v2",
        "rule_atoms",
        "rule_relationships",
    ):
        if not isinstance(draft.get(field_name, []), list):
            raise PortableInputError("INVALID_INPUT", f"draft.{field_name} must be a list")

    issues = [
        _draft_issue(raw, f"draft.issues[{index}]")
        for index, raw in enumerate(draft["issues"])
    ]
    findings = [
        _draft_finding(raw, f"draft.findings[{index}]")
        for index, raw in enumerate(draft["findings"])
    ]
    gaps = [
        _draft_gap(raw, f"draft.gaps[{index}]")
        for index, raw in enumerate(draft.get("gaps", []))
    ]
    lead_reviews: list[dict[str, Any]] = []
    for index, raw in enumerate(draft.get("lead_reviews", [])):
        path = f"draft.lead_reviews[{index}]"
        review = _require_object(raw, path)
        _require_keys(
            review,
            required={"lead_id", "disposition", "rationale"},
            optional={"gap_codes"},
            path=path,
        )
        disposition = review["disposition"]
        if disposition not in LEAD_REVIEW_DISPOSITIONS:
            raise PortableInputError("INVALID_INPUT", f"{path}.disposition is invalid")
        gap_codes = _string_list(review.get("gap_codes", []), f"{path}.gap_codes")
        if len(set(gap_codes)) != len(gap_codes):
            raise PortableInputError("INVALID_INPUT", f"{path}.gap_codes must be unique")
        if disposition == "gap" and not gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}.gap disposition requires gap_codes"
            )
        if disposition == "not_material" and gap_codes:
            raise PortableInputError(
                "INVALID_INPUT", f"{path}.not_material disposition cannot include gap_codes"
            )
        lead_reviews.append(
            {
                "lead_id": _nonblank(review["lead_id"], f"{path}.lead_id"),
                "disposition": disposition,
                "gap_codes": gap_codes,
                "rationale": _nonblank(review["rationale"], f"{path}.rationale"),
            }
        )
    lead_ids = [review["lead_id"] for review in lead_reviews]
    if len(set(lead_ids)) != len(lead_ids):
        raise PortableInputError(
            "INVALID_INPUT", "draft lead review identifiers must be unique"
        )
    coverage_contract_version = draft.get("coverage_contract_version")
    if coverage_contract_version is not None and (
        not isinstance(coverage_contract_version, str)
        or coverage_contract_version
        not in {COVERAGE_CONTRACT_VERSION, ATOMIC_COVERAGE_CONTRACT_VERSION}
    ):
        raise PortableInputError(
            "INVALID_INPUT",
            "draft.coverage_contract_version must be proposition-coverage-v1, "
            "proposition-coverage-v2, or null",
        )
    proposition_coverage = [
        _proposition_coverage_row(raw, f"draft.proposition_coverage[{index}]")
        for index, raw in enumerate(draft.get("proposition_coverage", []))
    ]
    coverage_ids = [row["coverage_id"] for row in proposition_coverage]
    if len(set(coverage_ids)) != len(coverage_ids):
        raise PortableInputError(
            "INVALID_INPUT", "draft coverage identifiers must be unique"
        )
    if coverage_contract_version == ATOMIC_COVERAGE_CONTRACT_VERSION and (
        lead_reviews or proposition_coverage
    ):
        raise PortableInputError(
            "INVALID_INPUT",
            "proposition-coverage-v2 requires lead_reviews and "
            "proposition_coverage to be empty",
        )
    parsed_brief = (
        None if draft.get("brief") is None else _brief(draft["brief"], "draft.brief")
    )
    if parsed_brief is not None and parsed_brief["structure_profile"] is None:
        raise PortableInputError(
            "INVALID_INPUT",
            "draft.brief.structure_profile must be regulatory-walk-v1",
        )
    unit_reviews = [
        _atomic_unit_review(raw, f"draft.unit_reviews[{index}]")
        for index, raw in enumerate(draft.get("unit_reviews", []))
    ]
    lead_dispositions_v2 = [
        _atomic_lead_disposition(raw, f"draft.lead_dispositions_v2[{index}]")
        for index, raw in enumerate(draft.get("lead_dispositions_v2", []))
    ]
    rule_atoms = [
        _atomic_rule_atom(raw, f"draft.rule_atoms[{index}]")
        for index, raw in enumerate(draft.get("rule_atoms", []))
    ]
    rule_relationships = [
        _atomic_rule_relationship(raw, f"draft.rule_relationships[{index}]")
        for index, raw in enumerate(draft.get("rule_relationships", []))
    ]
    for rows, identifier_field, label in (
        (unit_reviews, "unit_id", "unit review"),
        (
            lead_dispositions_v2,
            "lead_id",
            "lead disposition",
        ),
        (rule_atoms, "atom_id", "atom"),
        (
            rule_relationships,
            "relationship_id",
            "relationship",
        ),
    ):
        identifiers = [str(row[identifier_field]) for row in rows]
        if len(set(identifiers)) != len(identifiers):
            raise PortableInputError(
                "INVALID_INPUT", f"draft {label} identifiers must be unique"
            )
    parsed = _PortableDraft({
        "issues": issues,
        "findings": findings,
        "gaps": gaps,
        "lead_reviews": lead_reviews,
        "coverage_contract_version": coverage_contract_version,
        "proposition_coverage": proposition_coverage,
        "brief": parsed_brief,
    })
    if coverage_contract_version == ATOMIC_COVERAGE_CONTRACT_VERSION or any(
        (unit_reviews, lead_dispositions_v2, rule_atoms, rule_relationships)
    ):
        parsed.update(
            {
                "unit_reviews": unit_reviews,
                "lead_dispositions_v2": lead_dispositions_v2,
                "rule_atoms": rule_atoms,
                "rule_relationships": rule_relationships,
            }
        )
    return parsed


def _finalization_draft(value: object) -> dict[str, Any]:
    try:
        return _draft(value)
    except PortableInputError as error:
        if isinstance(value, dict) and "coverage_contract_version" in value:
            raw_contract = value.get("coverage_contract_version")
            if raw_contract == ATOMIC_COVERAGE_CONTRACT_VERSION and (
                value.get("lead_reviews") or value.get("proposition_coverage")
            ):
                reparsed_value = dict(value)
                reparsed_value["coverage_contract_version"] = COVERAGE_CONTRACT_VERSION
                try:
                    parsed = _draft(reparsed_value)
                except PortableInputError:
                    pass
                else:
                    parsed["coverage_contract_version"] = (
                        ATOMIC_COVERAGE_CONTRACT_VERSION
                    )
                    return parsed
            if (
                raw_contract is not None
                and raw_contract != COVERAGE_CONTRACT_VERSION
                and raw_contract != ATOMIC_COVERAGE_CONTRACT_VERSION
            ):
                reparsed_value = dict(value)
                reparsed_value["coverage_contract_version"] = None
                try:
                    parsed = _draft(reparsed_value)
                except PortableInputError:
                    pass
                else:
                    parsed["coverage_contract_version"] = raw_contract
                    return parsed
        raise error


def _all_matches(source_text: str, quote: object) -> list[tuple[int, int]]:
    if isinstance(quote, dict):
        raise TypeError("quote must be text")
    if not quote:
        return []
    if not isinstance(quote, str):
        raise TypeError("quote must be text")
    matches: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = source_text.find(quote, cursor)
        if start < 0:
            return matches
        matches.append((start, start + len(quote)))
        cursor = start + 1


def _content_tokens(text: str) -> list[str]:
    return [token for token in _TOKEN_RE.findall(text.casefold()) if token not in _STOP_WORDS]


def _support_status(claim_text: str, quotes: list[str]) -> str:
    claim_tokens = _content_tokens(claim_text)
    if len(claim_tokens) < 4:
        return "indeterminate"
    support_tokens = set(_content_tokens(" ".join(quotes)))
    if not support_tokens:
        return "unsupported"
    coverage = sum(token in support_tokens for token in claim_tokens) / len(claim_tokens)
    if coverage >= 0.80 and (set(claim_tokens) & _NEGATION_MARKERS) != (
        support_tokens & _NEGATION_MARKERS
    ):
        return "unsupported"
    return "supported" if coverage >= 0.60 else "unsupported"


def _review_item(
    claim_id: str, proposal_index: int, code: str, proposal: dict[str, Any]
) -> dict[str, Any]:
    identity = f"{claim_id}\0{proposal_index}\0{code}\0{proposal['source_id']}\0{proposal['quote']}"
    return {
        "review_id": f"review_{_sha256(identity.encode())[:24]}",
        "code": code,
        "message": "Proposed quote could not be resolved exactly and uniquely."
        if code != "PROPOSED_SOURCE_MISSING"
        else "Proposed citation references a source outside the bundle.",
        "related_ids": [claim_id, proposal["source_id"]],
        "context": {
            "source_id": proposal["source_id"],
            "quote": proposal["quote"],
            "occurrence": proposal["occurrence"],
        },
        "status": "pending",
    }


def _build_analysis(
    draft: dict[str, Any], sources: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    source_by_id = {source["source_id"]: source for source in sources}
    citations: list[dict[str, Any]] = []
    review_items: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for finding in draft["findings"]:
        claims: list[dict[str, Any]] = []
        for claim in finding["claims"]:
            claim_citations: list[dict[str, Any]] = []
            if claim["kind"] == "source_supported":
                for proposal_index, proposal in enumerate(claim["proposed_citations"]):
                    source = source_by_id.get(proposal["source_id"])
                    if source is None:
                        review_items.append(
                            _review_item(
                                claim["claim_id"],
                                proposal_index,
                                "PROPOSED_SOURCE_MISSING",
                                proposal,
                            )
                        )
                        continue
                    matches = _all_matches(source["normalized_text"], proposal["quote"])
                    occurrence = proposal["occurrence"]
                    resolved: tuple[int, int] | None = None
                    if len(matches) == 1 and occurrence in {None, 1}:
                        resolved = matches[0]
                    elif occurrence is not None and 1 <= occurrence <= len(matches):
                        resolved = matches[occurrence - 1]
                    if resolved is None:
                        code = (
                            "PROPOSED_QUOTE_AMBIGUOUS"
                            if len(matches) > 1
                            else "PROPOSED_QUOTE_NOT_FOUND"
                        )
                        review_items.append(
                            _review_item(claim["claim_id"], proposal_index, code, proposal)
                        )
                        continue
                    identity = "\0".join(
                        [
                            claim["claim_id"],
                            str(proposal_index),
                            proposal["source_id"],
                            proposal["quote"],
                            str(occurrence or ""),
                        ]
                    )
                    citation = {
                        "citation_id": f"cite_{_sha256(identity.encode())[:24]}",
                        "source_id": proposal["source_id"],
                        "start_char": resolved[0],
                        "end_char": resolved[1],
                        "quote": proposal["quote"],
                        "external_ids": {},
                    }
                    citations.append(citation)
                    claim_citations.append(citation)
            status = "indeterminate"
            if claim["kind"] == "source_supported" and claim_citations:
                status = _support_status(
                    claim["text"], [citation["quote"] for citation in claim_citations]
                )
            claims.append(
                {
                    "claim_id": claim["claim_id"],
                    "text": claim["text"],
                    "kind": claim["kind"],
                    "enforcement_roles": claim["enforcement_roles"],
                    "citation_ids": [citation["citation_id"] for citation in claim_citations],
                    "support_status": status,
                    "confidence": claim["confidence"],
                    "review_status": "pending",
                    "external_ids": {},
                }
            )
        findings.append(
            {
                "finding_id": finding["finding_id"],
                "issue_id": finding["issue_id"],
                "title": finding["title"],
                "jurisdiction": finding["jurisdiction"],
                "authority": finding["authority"],
                "severity": finding["severity"],
                "practical_implication": finding["practical_implication"],
                "claims": claims,
                "external_ids": {},
            }
        )
    return findings, citations, review_items


def _coverage_issue(
    code: str, lead_id: str, message: str, *related_ids: str
) -> dict[str, Any]:
    return {
        "code": code,
        "lead_id": lead_id,
        "message": message,
        "related_ids": list(related_ids),
    }


def _evaluate_provision_recall(
    inventory: dict[str, Any],
    draft: dict[str, Any],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_leads = inventory.get("leads", [])
    leads = [dict(lead) for lead in raw_leads if isinstance(lead, dict)] if isinstance(
        raw_leads, list
    ) else []
    lead_by_id = {
        lead["lead_id"]: lead
        for lead in leads
        if isinstance(lead.get("lead_id"), str) and lead["lead_id"]
    }
    reviews = {review["lead_id"]: review for review in draft["lead_reviews"]}
    issues: list[dict[str, Any]] = []
    for review in draft["lead_reviews"]:
        if review["lead_id"] not in lead_by_id:
            issues.append(
                _coverage_issue(
                    "PROVISION_LEAD_UNKNOWN",
                    review["lead_id"],
                    "Lead review references an identifier outside the prepared inventory.",
                )
            )

    built_findings, built_citations, _ = _build_analysis(draft, sources)
    category_by_issue = {
        issue["issue_id"]: issue["category"] for issue in draft["issues"]
    }
    citation_by_id = {
        citation["citation_id"]: citation for citation in built_citations
    }
    exact_spans: list[dict[str, Any]] = []
    for finding in built_findings:
        category = category_by_issue.get(finding["issue_id"])
        if category is None:
            continue
        for claim in finding["claims"]:
            for citation_id in claim["citation_ids"]:
                citation = citation_by_id.get(citation_id)
                if citation is None:
                    continue
                exact_spans.append(
                    {
                        "source_id": citation["source_id"],
                        "category": category,
                        "start_char": citation["start_char"],
                        "end_char": citation["end_char"],
                        "finding_id": finding["finding_id"],
                        "claim_id": claim["claim_id"],
                    }
                )

    lead_results: list[dict[str, Any]] = []
    unresolved_ids: list[str] = []
    for lead in leads:
        lead_id = lead.get("lead_id")
        source_id = lead.get("source_id")
        category = lead.get("issue_category")
        start = lead.get("start_char")
        end = lead.get("end_char")
        review_required = lead.get("review_required", True)
        if (
            not isinstance(lead_id, str)
            or not isinstance(source_id, str)
            or not isinstance(category, str)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end <= start
            or not isinstance(review_required, bool)
        ):
            issues.append(
                _coverage_issue(
                    "PROVISION_INVENTORY_INVALID",
                    lead_id if isinstance(lead_id, str) else "unknown",
                    "Prepared provision lead is malformed.",
                )
            )
            continue
        overlaps = [
            span
            for span in exact_spans
            if span["source_id"] == source_id
            and span["category"] == category
            and span["start_char"] < end
            and start < span["end_char"]
        ]
        if overlaps:
            related_ids: list[str] = []
            for span in overlaps:
                for related_id in (span["finding_id"], span["claim_id"]):
                    if related_id not in related_ids:
                        related_ids.append(related_id)
            lead_results.append(
                {
                    "lead_id": lead_id,
                    "status": "finding",
                    "related_ids": related_ids,
                    "rationale": None,
                }
            )
            continue

        review = reviews.get(lead_id)
        if review is not None and review["disposition"] == "not_material":
            lead_results.append(
                {
                    "lead_id": lead_id,
                    "status": "not_material",
                    "related_ids": [],
                    "rationale": review["rationale"],
                }
            )
            continue
        if review is not None and review["disposition"] == "gap":
            matching_codes = {
                gap["code"]
                for gap in draft["gaps"]
                if gap["code"] in review["gap_codes"]
                and gap["category"] == category
                and source_id in gap["source_ids"]
            }
            if matching_codes == set(review["gap_codes"]):
                lead_results.append(
                    {
                        "lead_id": lead_id,
                        "status": "gap",
                        "related_ids": sorted(matching_codes),
                        "rationale": review["rationale"],
                    }
                )
                continue
            issues.append(
                _coverage_issue(
                    "PROVISION_LEAD_GAP_INVALID",
                    lead_id,
                    "Gap review must name an authored gap with the lead category and source.",
                    *review["gap_codes"],
                )
            )
        elif not review_required:
            lead_results.append(
                {
                    "lead_id": lead_id,
                    "status": "informational",
                    "related_ids": [],
                    "rationale": None,
                }
            )
            continue
        else:
            issues.append(
                _coverage_issue(
                    "PROVISION_LEAD_UNRESOLVED",
                    lead_id,
                    "Priority provision lead lacks overlapping exact evidence or an "
                    "explicit review.",
                    source_id,
                    category,
                )
            )
        unresolved_ids.append(lead_id)
        lead_results.append(
            {
                "lead_id": lead_id,
                "status": "unresolved",
                "related_ids": [],
                "rationale": review["rationale"] if review is not None else None,
            }
        )

    status_counts = Counter(str(result["status"]) for result in lead_results)
    resolved_counts = {
        status: count
        for status, count in sorted(status_counts.items())
        if status != "unresolved"
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "inventory_version": inventory.get("inventory_version"),
        "valid": not issues and not unresolved_ids,
        "lead_count": len(leads),
        "priority_lead_count": sum(
            lead.get("review_required", True) is True for lead in leads
        ),
        "resolved_counts": resolved_counts,
        "unresolved_lead_ids": sorted(unresolved_ids),
        "leads": lead_results,
        "issues": issues,
    }
    payload["coverage_review_hash"] = _sha256(_canonical_bytes(payload))
    return payload


def _proposition_issue(
    code: str, message: str, *related_ids: str
) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "related_ids": sorted(set(related_ids)),
    }


def _append_proposition_issue(
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    code: str,
    message: str,
    *related_ids: object,
) -> None:
    safe_ids = tuple(
        sorted(
            {
                value
                for value in related_ids
                if isinstance(value, str) and value.strip()
            }
        )
    )
    key = (code, message, safe_ids)
    if key in issue_keys:
        return
    issue_keys.add(key)
    issues.append(_proposition_issue(code, message, *safe_ids))


def _proposition_object_list(
    inventory: dict[str, Any],
    key: str,
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    raw_items = inventory.get(key)
    if not isinstance(raw_items, list):
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory collection is malformed.",
        )
        return []
    if any(not isinstance(item, dict) for item in raw_items):
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory contains a malformed target.",
        )
    return [item for item in raw_items if isinstance(item, dict)]


def _proposition_is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_proposition_count(
    inventory: dict[str, Any],
    field: str,
    expected: int,
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    value = inventory.get(field)
    if not _proposition_is_int(value) or value != expected:
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory count is inconsistent.",
        )


def _proposition_source_index(
    sources: list[dict[str, Any]],
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> dict[str, dict[str, Any]]:
    valid_sources: list[dict[str, Any]] = []
    for source in sources:
        if (
            isinstance(source, dict)
            and isinstance(source.get("source_id"), str)
            and source["source_id"].strip()
            and isinstance(source.get("normalized_text"), str)
        ):
            valid_sources.append(source)
        else:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a malformed record.",
            )
    counts = Counter(str(source["source_id"]) for source in valid_sources)
    for source_id, count in sorted(counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a duplicate identifier.",
                source_id,
            )
    return {
        str(source["source_id"]): source
        for source in sorted(valid_sources, key=lambda item: str(item["source_id"]))
        if counts[str(source["source_id"])] == 1
    }


def _proposition_target_identity(
    item: dict[str, Any], id_key: str
) -> str | None:
    target_id = item.get(id_key)
    return target_id if isinstance(target_id, str) and target_id.strip() else None


def _validate_portable_unit_targets(
    unit_objects: list[dict[str, Any]],
    source_by_id: dict[str, dict[str, Any]],
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[list[dict[str, Any]], set[str]]:
    declared_ids = {
        target_id
        for item in unit_objects
        if (target_id := _proposition_target_identity(item, "unit_id")) is not None
    }
    id_counts = Counter(
        target_id
        for item in unit_objects
        if (target_id := _proposition_target_identity(item, "unit_id")) is not None
    )
    for target_id, count in sorted(id_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared source units contain a duplicate identifier.",
                target_id,
            )

    targets: list[dict[str, Any]] = []
    for item in unit_objects:
        unit_id = _proposition_target_identity(item, "unit_id")
        source_id = item.get("source_id")
        start = item.get("start_char")
        end = item.get("end_char")
        excerpt = item.get("excerpt")
        source = source_by_id.get(source_id) if isinstance(source_id, str) else None
        valid = (
            unit_id is not None
            and id_counts[unit_id] == 1
            and isinstance(source_id, str)
            and source is not None
            and _proposition_is_int(start)
            and _proposition_is_int(end)
            and 0 <= start < end <= len(source["normalized_text"])
            and isinstance(excerpt, str)
            and excerpt == source["normalized_text"][start:end]
            and item.get("coverage_required") is True
        )
        if not valid:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared source unit is malformed or is not an exact source slice.",
                unit_id,
                source_id,
            )
            continue
        targets.append(
            {
                "target_id": unit_id,
                "source_id": source_id,
                "start_char": start,
                "end_char": end,
                "category": None,
            }
        )
    return targets, declared_ids


def _validate_portable_lead_targets(
    lead_objects: list[dict[str, Any]],
    source_by_id: dict[str, dict[str, Any]],
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[list[dict[str, Any]], set[str]]:
    declared_ids = {
        target_id
        for item in lead_objects
        if (target_id := _proposition_target_identity(item, "lead_id")) is not None
    }
    id_counts = Counter(
        target_id
        for item in lead_objects
        if (target_id := _proposition_target_identity(item, "lead_id")) is not None
    )
    for target_id, count in sorted(id_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared provision leads contain a duplicate identifier.",
                target_id,
            )

    targets: list[dict[str, Any]] = []
    for item in lead_objects:
        lead_id = _proposition_target_identity(item, "lead_id")
        source_id = item.get("source_id")
        start = item.get("start_char")
        end = item.get("end_char")
        excerpt = item.get("excerpt")
        category = item.get("issue_category")
        topic = item.get("topic")
        source = source_by_id.get(source_id) if isinstance(source_id, str) else None
        valid = (
            lead_id is not None
            and id_counts[lead_id] == 1
            and isinstance(source_id, str)
            and source is not None
            and _proposition_is_int(start)
            and _proposition_is_int(end)
            and 0 <= start < end <= len(source["normalized_text"])
            and isinstance(excerpt, str)
            and excerpt == source["normalized_text"][start:end]
            and isinstance(category, str)
            and category in ISSUE_CATEGORIES
            and isinstance(topic, str)
            and bool(topic.strip())
            and isinstance(item.get("review_required"), bool)
        )
        if not valid:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared provision lead is malformed or is not an exact source slice.",
                lead_id,
                source_id,
            )
            continue
        targets.append(
            {
                "target_id": lead_id,
                "source_id": source_id,
                "start_char": start,
                "end_char": end,
                "category": category,
            }
        )
    return targets, declared_ids


def _add_portable_brief_claim_ids(
    locations: dict[str, list[str]], claim_ids: object, path: str
) -> None:
    if not isinstance(claim_ids, list):
        return
    for claim_id in claim_ids:
        if isinstance(claim_id, str) and path not in locations[claim_id]:
            locations[claim_id].append(path)


def _walk_portable_brief_block(
    block: dict[str, Any], path: str, locations: dict[str, list[str]]
) -> None:
    if block.get("purpose") != "legal_analysis":
        return
    if block.get("kind") == "paragraph":
        _add_portable_brief_claim_ids(locations, block.get("claim_ids"), path)
        return
    if block.get("kind") in {"bullet_list", "numbered_list"}:
        items = block.get("items")
        if isinstance(items, list):
            for index, item in enumerate(items):
                if isinstance(item, dict):
                    _add_portable_brief_claim_ids(
                        locations,
                        item.get("claim_ids"),
                        f"{path}.items[{index}]",
                    )
        return
    rows = block.get("rows")
    if isinstance(rows, list):
        for index, row in enumerate(rows):
            if isinstance(row, dict):
                _add_portable_brief_claim_ids(
                    locations,
                    row.get("claim_ids"),
                    f"{path}.rows[{index}]",
                )


def _portable_brief_claim_locations(brief: object) -> dict[str, list[str]]:
    locations: dict[str, list[str]] = defaultdict(list)
    if not isinstance(brief, dict):
        return {}
    executive_summary = brief.get("executive_summary")
    if isinstance(executive_summary, list):
        for block_index, block in enumerate(executive_summary):
            if isinstance(block, dict):
                _walk_portable_brief_block(
                    block,
                    f"brief.executive_summary[{block_index}]",
                    locations,
                )
    sections = brief.get("sections")
    if isinstance(sections, list):
        for section_index, section in enumerate(sections):
            if not isinstance(section, dict):
                continue
            section_path = f"brief.sections[{section_index}]"
            blocks = section.get("blocks")
            if isinstance(blocks, list):
                for block_index, block in enumerate(blocks):
                    if isinstance(block, dict):
                        _walk_portable_brief_block(
                            block,
                            f"{section_path}.blocks[{block_index}]",
                            locations,
                        )
            subsections = section.get("subsections")
            if not isinstance(subsections, list):
                continue
            for subsection_index, subsection in enumerate(subsections):
                if not isinstance(subsection, dict):
                    continue
                subsection_path = (
                    f"{section_path}.subsections[{subsection_index}]"
                )
                subsection_blocks = subsection.get("blocks")
                if isinstance(subsection_blocks, list):
                    for block_index, block in enumerate(subsection_blocks):
                        if isinstance(block, dict):
                            _walk_portable_brief_block(
                                block,
                                f"{subsection_path}.blocks[{block_index}]",
                                locations,
                            )
    return {
        claim_id: sorted(paths)
        for claim_id, paths in sorted(locations.items())
    }


def _portable_core_draft_snapshot(draft: object) -> dict[str, Any] | None:
    if not isinstance(draft, _PortableDraft):
        return None
    raw_issues = draft.get("issues")
    raw_findings = draft.get("findings")
    raw_gaps = draft.get("gaps")
    if not all(isinstance(value, list) for value in (raw_issues, raw_findings, raw_gaps)):
        return None
    assert isinstance(raw_issues, list)
    assert isinstance(raw_findings, list)
    assert isinstance(raw_gaps, list)
    try:
        issues = []
        for index, issue in enumerate(raw_issues):
            if not isinstance(issue, _PortableIssue):
                raise TypeError
            issues.append(_draft_issue(dict(issue), f"draft.issues[{index}]"))

        findings = []
        for finding_index, finding in enumerate(raw_findings):
            if not isinstance(finding, _PortableFinding):
                raise TypeError
            claims = finding.get("claims")
            if not isinstance(claims, list):
                raise TypeError
            finding_value = dict(finding)
            finding_value["claims"] = []
            normalized_finding = _draft_finding(
                finding_value, f"draft.findings[{finding_index}]"
            )
            normalized_claims: list[_PortableClaim] = []
            for claim_index, claim in enumerate(claims):
                if not isinstance(claim, _PortableClaim):
                    raise TypeError
                citations = claim.get("proposed_citations")
                if not isinstance(citations, list) or any(
                    not isinstance(citation, _PortableCitation)
                    for citation in citations
                ):
                    raise TypeError
                if any(
                    not isinstance(citation.get("source_id"), str)
                    for citation in citations
                ):
                    raise TypeError
                claim_value = dict(claim)
                claim_value["proposed_citations"] = []
                normalized_claim = _draft_claim(
                    claim_value,
                    f"draft.findings[{finding_index}].claims[{claim_index}]",
                )
                normalized_claim["proposed_citations"] = [
                    _PortableCitation(dict(citation)) for citation in citations
                ]
                normalized_claims.append(normalized_claim)
            normalized_finding["claims"] = normalized_claims
            findings.append(normalized_finding)

        gaps = []
        for index, gap in enumerate(raw_gaps):
            if not isinstance(gap, _PortableGap):
                raise TypeError
            gaps.append(_draft_gap(dict(gap), f"draft.gaps[{index}]"))
    except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
        return None
    snapshot = dict(draft)
    snapshot.update({"issues": issues, "findings": findings, "gaps": gaps})
    return snapshot


def _portable_proposition_claim_index(
    draft: dict[str, Any],
    sources: list[dict[str, Any]],
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[dict[str, dict[str, Any]], bool]:
    try:
        snapshot = _portable_core_draft_snapshot(draft)
        if snapshot is None:
            raise TypeError
        built_findings, built_citations, _ = _build_analysis(snapshot, sources)
    except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The analysis draft could not be reconciled into exact evidence.",
        )
        return {}, False

    draft_issues = snapshot["issues"]
    issue_counts = Counter(
        issue.get("issue_id")
        for issue in draft_issues
        if isinstance(issue, dict) and isinstance(issue.get("issue_id"), str)
    )
    category_by_issue: dict[str, str] = {}
    for issue in draft_issues:
        if not isinstance(issue, dict):
            continue
        issue_id = issue.get("issue_id")
        category = issue.get("category")
        if not isinstance(issue_id, str) or not isinstance(category, str):
            continue
        if issue_counts[issue_id] > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built analysis issues contain a duplicate identifier.",
                issue_id,
            )
            continue
        category_by_issue[issue_id] = category

    citation_counts = Counter(
        citation.get("citation_id")
        for citation in built_citations
        if isinstance(citation.get("citation_id"), str)
    )
    citation_by_id = {
        str(citation["citation_id"]): citation
        for citation in built_citations
        if isinstance(citation.get("citation_id"), str)
        and citation_counts[citation["citation_id"]] == 1
    }
    for citation_id, count in sorted(citation_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built exact citations contain a duplicate identifier.",
                citation_id,
            )

    claim_counts = Counter(
        claim.get("claim_id")
        for finding in built_findings
        for claim in finding.get("claims", [])
        if isinstance(claim, dict) and isinstance(claim.get("claim_id"), str)
    )
    for claim_id, count in sorted(claim_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built analysis claims contain a duplicate identifier.",
                claim_id,
            )

    claims: dict[str, dict[str, Any]] = {}
    for finding in built_findings:
        category = category_by_issue.get(str(finding.get("issue_id")))
        for claim in finding.get("claims", []):
            claim_id = claim.get("claim_id")
            if not isinstance(claim_id, str) or claim_counts[claim_id] != 1:
                continue
            spans = [
                {
                    "source_id": citation["source_id"],
                    "start_char": citation["start_char"],
                    "end_char": citation["end_char"],
                }
                for citation_id in claim.get("citation_ids", [])
                if (citation := citation_by_id.get(citation_id)) is not None
            ]
            claims[claim_id] = {
                "kind": claim.get("kind"),
                "category": category,
                "spans": spans,
            }
    return claims, True


def _portable_validated_coverage_rows(
    value: object,
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The proposition coverage ledger is malformed.",
        )
        return []
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        related_ids: tuple[str, ...] = ()
        if isinstance(row, dict):
            coverage_id = row.get("coverage_id")
            if isinstance(coverage_id, str) and coverage_id.strip():
                related_ids = (coverage_id,)
        try:
            rows.append(
                _proposition_coverage_row(
                    row,
                    f"draft.proposition_coverage[{index}]",
                )
            )
        except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "The proposition coverage ledger contains a malformed row.",
                *related_ids,
            )
    return rows


def _portable_span_overlaps_target(
    span: dict[str, Any], target: dict[str, Any]
) -> bool:
    return (
        span["source_id"] == target["source_id"]
        and span["start_char"] < target["end_char"]
        and target["start_char"] < span["end_char"]
    )


def _evaluate_proposition_coverage(
    source_unit_inventory: dict[str, Any],
    evidence_inventory: dict[str, Any],
    draft: dict[str, Any],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    if draft.get("coverage_contract_version") != COVERAGE_CONTRACT_VERSION:
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The draft coverage contract is missing or mismatched.",
        )
    if source_unit_inventory.get("inventory_version") != SOURCE_UNIT_INVENTORY_VERSION:
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The prepared source-unit inventory version is missing or mismatched.",
        )
    if evidence_inventory.get("inventory_version") != PROVISION_LEADS_VERSION:
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The prepared provision-lead inventory version is missing or mismatched.",
        )

    source_by_id = _proposition_source_index(
        sources,
        issues=issues,
        issue_keys=issue_keys,
    )
    unit_objects = _proposition_object_list(
        source_unit_inventory,
        "units",
        issues=issues,
        issue_keys=issue_keys,
    )
    lead_objects = _proposition_object_list(
        evidence_inventory,
        "leads",
        issues=issues,
        issue_keys=issue_keys,
    )
    _check_proposition_count(
        source_unit_inventory,
        "unit_count",
        len(unit_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    _check_proposition_count(
        source_unit_inventory,
        "required_unit_count",
        len(unit_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    _check_proposition_count(
        evidence_inventory,
        "lead_count",
        len(lead_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    units, declared_unit_ids = _validate_portable_unit_targets(
        unit_objects,
        source_by_id,
        issues=issues,
        issue_keys=issue_keys,
    )
    leads, declared_lead_ids = _validate_portable_lead_targets(
        lead_objects,
        source_by_id,
        issues=issues,
        issue_keys=issue_keys,
    )
    unit_by_id = {str(target["target_id"]): target for target in units}
    lead_by_id = {str(target["target_id"]): target for target in leads}
    claims, build_available = _portable_proposition_claim_index(
        draft,
        sources,
        issues=issues,
        issue_keys=issue_keys,
    )
    claim_locations = _portable_brief_claim_locations(draft.get("brief"))

    raw_gaps = draft.get("gaps")
    gaps = raw_gaps if isinstance(raw_gaps, list) else []
    gap_counts = Counter(
        gap.get("code")
        for gap in gaps
        if isinstance(gap, dict) and isinstance(gap.get("code"), str)
    )
    gap_by_code = {
        str(gap["code"]): gap
        for gap in gaps
        if isinstance(gap, dict)
        and isinstance(gap.get("code"), str)
        and gap_counts[gap["code"]] == 1
    }
    for gap_code, count in sorted(gap_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_GAP_INVALID",
                "Authored gaps contain a duplicate mapping code.",
                gap_code,
            )

    rows = _portable_validated_coverage_rows(
        draft.get("proposition_coverage"),
        issues=issues,
        issue_keys=issue_keys,
    )
    row_id_counts = Counter(str(row["coverage_id"]) for row in rows)
    for coverage_id, count in sorted(row_id_counts.items()):
        if count > 1:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Proposition coverage identifiers must be unique.",
                coverage_id,
            )

    coverage_by_unit: dict[str, set[str]] = defaultdict(set)
    coverage_by_lead: dict[str, set[str]] = defaultdict(set)
    row_results: list[dict[str, Any]] = []
    disposition_counts: Counter[str] = Counter()
    for row in sorted(
        rows,
        key=lambda item: (str(item["coverage_id"]), _canonical_bytes(item)),
    ):
        coverage_id = str(row["coverage_id"])
        category = str(row["category"])
        disposition = str(row["disposition"])
        proposition_type = str(row["proposition_type"])
        disposition_counts[disposition] += 1
        for unit_id in row["unit_ids"]:
            if unit_id in declared_unit_ids:
                coverage_by_unit[unit_id].add(coverage_id)
            else:
                _append_proposition_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_TARGET_UNKNOWN",
                    "Coverage row references a unit outside the prepared inventory.",
                    coverage_id,
                    unit_id,
                )
        for lead_id in row["lead_ids"]:
            if lead_id in declared_lead_ids:
                coverage_by_lead[lead_id].add(coverage_id)
            else:
                _append_proposition_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_TARGET_UNKNOWN",
                    "Coverage row references a lead outside the prepared inventory.",
                    coverage_id,
                    lead_id,
                )
        if disposition in {"covered", "gap"}:
            for lead_id in row["lead_ids"]:
                target = lead_by_id.get(lead_id)
                if target is not None and target["category"] != category:
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_ROW_INVALID",
                        "Coverage row category is incompatible with a referenced lead.",
                        coverage_id,
                        lead_id,
                    )

        target_sources = {
            str(target["source_id"])
            for target_id in (*row["unit_ids"], *row["lead_ids"])
            if (target := unit_by_id.get(target_id) or lead_by_id.get(target_id))
            is not None
        }
        valid_gap_codes: set[str] = set()
        for gap_code in row["gap_codes"]:
            gap = gap_by_code.get(gap_code)
            source_ids = gap.get("source_ids") if gap is not None else None
            if (
                gap is None
                or gap.get("category") != category
                or not isinstance(source_ids, list)
                or len(source_ids) != len(set(source_ids))
                or set(source_ids) != target_sources
            ):
                _append_proposition_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_GAP_INVALID",
                    "Coverage gap must be unique, authored, category-matched, and target-bound.",
                    coverage_id,
                    gap_code,
                )
                continue
            valid_gap_codes.add(gap_code)

        elements = row["elements"]
        not_established = (
            [
                name
                for name in _COVERAGE_ELEMENT_FIELDS
                if elements[name]["status"] == "not_established"
            ]
            if isinstance(elements, dict)
            else []
        )
        if disposition == "covered" and not valid_gap_codes:
            for element_name in not_established:
                _append_proposition_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_ELEMENT_INCOMPLETE",
                    "A not-established element lacks a valid authored row gap.",
                    coverage_id,
                    element_name,
                )

        eligible_claims: list[dict[str, Any]] = []
        if disposition == "covered" and build_available:
            for claim_id in row["claim_ids"]:
                claim = claims.get(claim_id)
                if claim is None:
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_UNKNOWN",
                        "Covered row references a claim outside the built analysis.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if claim["kind"] != "source_supported":
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_NOT_SOURCE_SUPPORTED",
                        "Covered row references a claim that is not source-supported.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if claim["category"] != category:
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_ROW_INVALID",
                        "Covered claim category does not match the coverage row.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if not claim_locations.get(claim_id):
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_NOT_VISIBLE",
                        "Covered claim is absent from visible legal analysis.",
                        coverage_id,
                        claim_id,
                    )
                if not claim["spans"]:
                    _append_proposition_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_EVIDENCE_OUTSIDE_TARGET",
                        "Covered claim has no resolved exact source evidence.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                eligible_claims.append(claim)
            if eligible_claims:
                exact_spans = [
                    span
                    for claim in eligible_claims
                    for span in claim["spans"]
                ]
                for target_id in row["unit_ids"]:
                    target = unit_by_id.get(target_id)
                    if target is not None and not any(
                        _portable_span_overlaps_target(span, target)
                        for span in exact_spans
                    ):
                        _append_proposition_issue(
                            issues,
                            issue_keys,
                            "COVERAGE_EVIDENCE_OUTSIDE_TARGET",
                            "Exact claim evidence does not overlap a referenced unit.",
                            coverage_id,
                            target_id,
                        )
                for target_id in row["lead_ids"]:
                    target = lead_by_id.get(target_id)
                    if target is not None and not any(
                        _portable_span_overlaps_target(span, target)
                        for span in exact_spans
                    ):
                        _append_proposition_issue(
                            issues,
                            issue_keys,
                            "COVERAGE_EVIDENCE_OUTSIDE_TARGET",
                            "Exact claim evidence does not overlap a referenced lead.",
                            coverage_id,
                            target_id,
                        )

        brief_locations = sorted(
            {
                path
                for claim_id in row["claim_ids"]
                for path in claim_locations.get(claim_id, [])
            }
        )
        row_results.append(
            {
                "coverage_id": coverage_id,
                "category": category,
                "proposition_type": proposition_type,
                "disposition": disposition,
                "unit_ids": sorted(row["unit_ids"]),
                "lead_ids": sorted(row["lead_ids"]),
                "claim_ids": sorted(row["claim_ids"]),
                "gap_codes": sorted(row["gap_codes"]),
                "brief_locations": brief_locations,
                "rationale": row["rationale"],
                "valid": not any(
                    coverage_id in issue["related_ids"] for issue in issues
                ),
            }
        )

    for target in units:
        target_id = str(target["target_id"])
        if not coverage_by_unit[target_id]:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_TARGET_UNRESOLVED",
                "Required source unit has no proposition coverage disposition.",
                target_id,
            )
    for target in leads:
        target_id = str(target["target_id"])
        if not coverage_by_lead[target_id]:
            _append_proposition_issue(
                issues,
                issue_keys,
                "COVERAGE_TARGET_UNRESOLVED",
                "Provision lead has no proposition coverage disposition.",
                target_id,
            )
    issues.sort(
        key=lambda issue: (
            str(issue["code"]),
            tuple(str(value) for value in issue["related_ids"]),
            str(issue["message"]),
        )
    )
    unit_results = [
        {
            "unit_id": target["target_id"],
            "source_id": target["source_id"],
            "status": (
                "mapped"
                if coverage_by_unit[str(target["target_id"])]
                else "unresolved"
            ),
            "coverage_ids": sorted(
                coverage_by_unit[str(target["target_id"])]
            ),
        }
        for target in sorted(
            units,
            key=lambda item: (
                item["source_id"],
                item["start_char"],
                item["end_char"],
                item["target_id"],
            ),
        )
    ]
    lead_results = [
        {
            "lead_id": target["target_id"],
            "source_id": target["source_id"],
            "issue_category": target["category"],
            "status": (
                "mapped"
                if coverage_by_lead[str(target["target_id"])]
                else "unresolved"
            ),
            "coverage_ids": sorted(
                coverage_by_lead[str(target["target_id"])]
            ),
        }
        for target in sorted(
            leads,
            key=lambda item: (
                item["source_id"],
                item["start_char"],
                item["end_char"],
                item["target_id"],
            ),
        )
    ]
    return {
        "schema_version": "1.0",
        "valid": not issues,
        "target_counts": {"units": len(unit_objects), "leads": len(lead_objects)},
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "units": unit_results,
        "leads": lead_results,
        "rows": row_results,
        "issues": issues,
    }


def _evaluate_coverage_closure(
    evidence_inventory: dict[str, Any],
    source_unit_inventory: dict[str, Any],
    draft: dict[str, Any],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    if draft.get("coverage_contract_version") == ATOMIC_COVERAGE_CONTRACT_VERSION:
        return cast(
            dict[str, Any],
            _evaluate_portable_atomic_coverage(
                source_unit_inventory,
                evidence_inventory,
                draft,
                sources,
            ),
        )
    proposition = _evaluate_proposition_coverage(
        source_unit_inventory,
        evidence_inventory,
        draft,
        sources,
    )
    recall_draft = draft
    if draft.get("coverage_contract_version") == COVERAGE_CONTRACT_VERSION:
        projected_reviews = _project_strict_lead_reviews(proposition)
        recall_draft = dict(draft)
        recall_draft["lead_reviews"] = projected_reviews or []
    lead_recall = _evaluate_provision_recall(
        evidence_inventory, recall_draft, sources
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "coverage_contract_version": COVERAGE_CONTRACT_VERSION,
        "valid": lead_recall["valid"] is True and proposition["valid"] is True,
        "lead_recall": lead_recall,
        "proposition_coverage": proposition,
    }
    payload["coverage_review_hash"] = _sha256(_canonical_bytes(payload))
    return payload


def _project_strict_lead_reviews(
    proposition: dict[str, Any],
) -> list[dict[str, Any]] | None:
    if proposition.get("valid") is not True:
        return None
    rows = proposition.get("rows")
    if not isinstance(rows, list):
        return None
    projected: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("valid") is not True:
            return None
        disposition = row.get("disposition")
        if disposition not in {"gap", "not_material"}:
            continue
        coverage_id = row.get("coverage_id")
        rationale = row.get("rationale")
        lead_ids = row.get("lead_ids")
        gap_codes = row.get("gap_codes")
        if (
            not isinstance(coverage_id, str)
            or not coverage_id.strip()
            or not isinstance(rationale, str)
            or not rationale.strip()
            or not isinstance(lead_ids, list)
            or any(not isinstance(lead_id, str) or not lead_id for lead_id in lead_ids)
            or not isinstance(gap_codes, list)
            or any(not isinstance(code, str) or not code for code in gap_codes)
            or (disposition == "gap" and not gap_codes)
            or (disposition == "not_material" and gap_codes)
        ):
            return None
        for lead_id in lead_ids:
            state = projected.setdefault(
                lead_id,
                {"gap_codes": set(), "gap_rows": set(), "not_material_rows": set()},
            )
            if disposition == "gap":
                state["gap_codes"].update(gap_codes)
                state["gap_rows"].add(coverage_id)
            else:
                state["not_material_rows"].add(coverage_id)
    reviews: list[dict[str, Any]] = []
    for lead_id, state in sorted(projected.items()):
        gap_rows = sorted(state["gap_rows"])
        not_material_rows = sorted(state["not_material_rows"])
        if gap_rows:
            disposition = "gap"
            gap_codes = sorted(state["gap_codes"])
            coverage_ids = gap_rows
        else:
            disposition = "not_material"
            gap_codes = []
            coverage_ids = not_material_rows
        reviews.append(
            {
                "lead_id": lead_id,
                "disposition": disposition,
                "gap_codes": gap_codes,
                "rationale": (
                    "Projected from strict proposition coverage rows: "
                    + ", ".join(coverage_ids)
                    + "."
                ),
            }
        )
    return reviews


def _atomic_issue(code: str, message: str, *related_ids: object) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "related_ids": sorted(
            {
                value
                for value in related_ids
                if isinstance(value, str) and value.strip()
            }
        ),
    }


def _append_atomic_issue(
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    code: str,
    message: str,
    *related_ids: object,
) -> None:
    issue = _atomic_issue(code, message, *related_ids)
    raw_ids = issue["related_ids"]
    safe_ids = tuple(str(value) for value in raw_ids) if isinstance(raw_ids, list) else ()
    key = (code, message, safe_ids)
    if key not in issue_keys:
        issue_keys.add(key)
        issues.append(issue)


def _atomic_issue_sort_ids(issue: dict[str, object]) -> tuple[str, ...]:
    related_ids = issue.get("related_ids")
    return (
        tuple(str(value) for value in related_ids)
        if isinstance(related_ids, list)
        else ()
    )


def _atomic_related_issue(issues: list[dict[str, object]], identifier: str) -> bool:
    return any(
        isinstance((related_ids := issue.get("related_ids")), list)
        and identifier in related_ids
        for issue in issues
    )


def _atomic_issue_has_related_ids(
    issue: dict[str, object], *identifiers: str
) -> bool:
    related_ids = issue.get("related_ids")
    return isinstance(related_ids, list) and all(
        identifier in related_ids for identifier in identifiers
    )


def _portable_source_datetime(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    timestamp: float | None = None
    if isinstance(value, (int, float)):
        timestamp = float(value)
    elif isinstance(value, str) and re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value):
        try:
            timestamp = float(value)
        except ValueError:
            return None
    if timestamp is not None:
        if not math.isfinite(timestamp):
            return None
        if abs(timestamp) > 20_000_000_000:
            timestamp /= 1000
        try:
            parsed = datetime.fromtimestamp(timestamp, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        if not isinstance(value, str) or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}(?:[Tt _]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?"
            r"(?:[Zz]|[+-]\d{2}:?\d{2})?)?",
            value,
        ) is None:
            return None
        try:
            normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    return parsed.isoformat().replace("+00:00", "Z")


def _portable_source_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str):
        stripped = value.strip()
        if re.fullmatch(r"[+-]?\d+(?:\.0+)?", stripped):
            return int(stripped.split(".", 1)[0])
    return None


def _portable_source_boolean(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.casefold()
        if normalized in {"1", "t", "true", "y", "yes", "on"}:
            return True
        if normalized in {"0", "f", "false", "n", "no", "off"}:
            return False
    return None


def _portable_source_record(source: object) -> dict[str, Any] | None:
    if not isinstance(source, dict):
        return None
    allowed = {
        "source_id",
        "origin",
        "display_name",
        "retrieved_at",
        "content_hash",
        "media_type",
        "normalized_text",
        "normalization_warnings",
        "canonical_url",
        "title",
        "publisher",
        "jurisdiction",
        "authority_type",
        "citation",
        "effective_date",
        "supersession",
        "language",
        "license_assertion",
        "source_quality",
        "source_role",
        "fetch_status",
        "error",
        "external_ids",
    }
    required = {"source_id", "origin", "display_name", "retrieved_at", "media_type"}
    if not required <= source.keys() or set(source) - allowed:
        return None
    if any(
        not isinstance(source.get(field), str) or not str(source[field]).strip()
        for field in ("source_id", "origin", "display_name", "media_type")
    ):
        return None
    retrieved_at = _portable_source_datetime(source.get("retrieved_at"))
    if retrieved_at is None:
        return None
    content_hash = source.get("content_hash")
    if content_hash is not None and (
        not isinstance(content_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", content_hash) is None
    ):
        return None
    if not isinstance(source.get("normalized_text", ""), str):
        return None
    warnings = source.get("normalization_warnings", [])
    if not isinstance(warnings, list) or any(not isinstance(item, str) for item in warnings):
        return None
    for field in (
        "title",
        "publisher",
        "jurisdiction",
        "authority_type",
        "citation",
        "effective_date",
        "supersession",
        "language",
    ):
        value = source.get(field)
        if value is not None and not isinstance(value, str):
            return None
    try:
        canonical_url = _canonical_public_url(
            source.get("canonical_url"), "source.canonical_url"
        )
    except PortableInputError:
        return None
    if isinstance(source.get("language"), str) and not str(source["language"]).strip():
        return None
    license_assertion = source.get("license_assertion", "unknown")
    if not isinstance(license_assertion, str) or not license_assertion.strip():
        return None
    if source.get("source_quality", "unknown") not in SOURCE_QUALITIES:
        return None
    if source.get("source_role") not in SOURCE_ROLES | {None}:
        return None
    fetch_status = source.get("fetch_status", "succeeded")
    if fetch_status not in {"succeeded", "failed", "pending"}:
        return None
    error = source.get("error")
    if fetch_status == "succeeded" and content_hash is None:
        return None
    if fetch_status == "failed" and not isinstance(error, dict):
        return None
    normalized_error: dict[str, object] | None = None
    if error is not None:
        if not isinstance(error, dict):
            return None
        if not {"category", "message"} <= error.keys() or set(error) - {
            "category",
            "retryable",
            "message",
            "provider_status_code",
        }:
            return None
        if any(
            not isinstance(error.get(field), str) or not str(error[field]).strip()
            for field in ("category", "message")
        ):
            return None
        retryable = _portable_source_boolean(error.get("retryable", False))
        if retryable is None:
            return None
        provider_status = error.get("provider_status_code")
        normalized_provider_status = (
            None
            if provider_status is None
            else _portable_source_integer(provider_status)
        )
        if provider_status is not None and normalized_provider_status is None:
            return None
        normalized_error = {
            "category": str(error["category"]).strip(),
            "retryable": retryable,
            "message": str(error["message"]).strip(),
            "provider_status_code": normalized_provider_status,
        }
    external_ids = source.get("external_ids", {})
    if not isinstance(external_ids, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in external_ids.items()
    ):
        return None
    language = source.get("language")
    return {
        "source_id": str(source["source_id"]).strip(),
        "origin": str(source["origin"]).strip(),
        "display_name": str(source["display_name"]).strip(),
        "retrieved_at": retrieved_at,
        "content_hash": content_hash,
        "media_type": str(source["media_type"]).strip(),
        "normalized_text": source.get("normalized_text", ""),
        "normalization_warnings": list(warnings),
        "canonical_url": canonical_url,
        "title": source.get("title"),
        "publisher": source.get("publisher"),
        "jurisdiction": source.get("jurisdiction"),
        "authority_type": source.get("authority_type"),
        "citation": source.get("citation"),
        "effective_date": source.get("effective_date"),
        "supersession": source.get("supersession"),
        "language": language.strip() if isinstance(language, str) else None,
        "license_assertion": license_assertion.strip(),
        "source_quality": source.get("source_quality", "unknown"),
        "source_role": source.get("source_role"),
        "fetch_status": fetch_status,
        "error": normalized_error,
        "external_ids": dict(external_ids),
    }


def _portable_source_record_valid(source: object) -> bool:
    return _portable_source_record(source) is not None


def _portable_atomic_target_indexes(
    source_unit_inventory: object,
    evidence_inventory: object,
    sources: object,
) -> tuple[dict[str, Any], list[dict[str, object]]]:
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    raw_sources = sources if isinstance(sources, list) else []
    if not isinstance(sources, list):
        _append_atomic_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared sources contain a malformed row.",
        )
    valid_sources: list[dict[str, Any]] = []
    for source in raw_sources:
        source_id = source.get("source_id") if isinstance(source, dict) else None
        normalized_source = _portable_source_record(source)
        if normalized_source is None:
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a malformed row.",
                source_id,
            )
            continue
        valid_sources.append(normalized_source)
    source_counts = Counter(str(source["source_id"]) for source in valid_sources)
    for source_id, count in sorted(source_counts.items()):
        if count > 1:
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a duplicate identifier.",
                source_id,
            )
    source_by_id = {
        str(source["source_id"]): source
        for source in sorted(valid_sources, key=lambda item: str(item["source_id"]))
        if source_counts[str(source["source_id"])] == 1
    }

    safe_units = source_unit_inventory if isinstance(source_unit_inventory, dict) else {}
    safe_leads = evidence_inventory if isinstance(evidence_inventory, dict) else {}

    def object_list(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
        raw_items = inventory.get(key)
        if not isinstance(raw_items, list):
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared coverage inventory collection is malformed.",
            )
            return []
        if any(not isinstance(item, dict) for item in raw_items):
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared coverage inventory contains a malformed target.",
            )
        return [dict(item) for item in raw_items if isinstance(item, dict)]

    unit_objects = object_list(safe_units, "units")
    lead_objects = object_list(safe_leads, "leads")
    for inventory, field_name, expected in (
        (safe_units, "unit_count", len(unit_objects)),
        (safe_units, "required_unit_count", len(unit_objects)),
        (safe_leads, "lead_count", len(lead_objects)),
    ):
        value = inventory.get(field_name)
        if not _proposition_is_int(value) or value != expected:
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared coverage inventory count is inconsistent.",
            )

    def targets(
        objects: list[dict[str, Any]],
        *,
        identifier_field: str,
        is_lead: bool,
    ) -> tuple[list[dict[str, Any]], set[str]]:
        declared_ids = {
            target_id
            for item in objects
            if isinstance((target_id := item.get(identifier_field)), str)
            and target_id.strip()
        }
        identifier_counts = Counter(
            item.get(identifier_field)
            for item in objects
            if isinstance(item.get(identifier_field), str)
            and str(item[identifier_field]).strip()
        )
        duplicate_message = (
            "Prepared provision leads contain a duplicate identifier."
            if is_lead
            else "Prepared source units contain a duplicate identifier."
        )
        malformed_message = (
            "Prepared provision lead is malformed or is not an exact source slice."
            if is_lead
            else "Prepared source unit is malformed or is not an exact source slice."
        )
        for target_id, count in sorted(identifier_counts.items()):
            if count > 1:
                _append_atomic_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_ROW_INVALID",
                    duplicate_message,
                    target_id,
                )
        valid_targets: list[dict[str, Any]] = []
        for item in objects:
            target_id = item.get(identifier_field)
            source_id = item.get("source_id")
            start = item.get("start_char")
            end = item.get("end_char")
            excerpt = item.get("excerpt")
            source = source_by_id.get(source_id) if isinstance(source_id, str) else None
            category = item.get("issue_category")
            topic = item.get("topic")
            valid = (
                isinstance(target_id, str)
                and bool(target_id.strip())
                and identifier_counts[target_id] == 1
                and isinstance(source_id, str)
                and source is not None
                and _proposition_is_int(start)
                and _proposition_is_int(end)
                and 0 <= start < end <= len(source["normalized_text"])
                and isinstance(excerpt, str)
                and excerpt == source["normalized_text"][start:end]
                and (
                    (
                        isinstance(category, str)
                        and category in ISSUE_CATEGORIES
                        and isinstance(topic, str)
                        and bool(topic.strip())
                        and isinstance(item.get("review_required"), bool)
                    )
                    if is_lead
                    else item.get("coverage_required") is True
                )
            )
            if not valid:
                _append_atomic_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_ROW_INVALID",
                    malformed_message,
                    target_id,
                    source_id,
                )
                continue
            valid_targets.append(
                {
                    "target_id": target_id,
                    "source_id": source_id,
                    "start_char": start,
                    "end_char": end,
                    "category": category if is_lead else None,
                }
            )
        return valid_targets, declared_ids

    units, declared_unit_ids = targets(
        unit_objects, identifier_field="unit_id", is_lead=False
    )
    leads, declared_lead_ids = targets(
        lead_objects, identifier_field="lead_id", is_lead=True
    )
    return (
        {
            "source_by_id": source_by_id,
            "unit_objects": unit_objects,
            "lead_objects": lead_objects,
            "units": units,
            "leads": leads,
            "declared_unit_ids": declared_unit_ids,
            "declared_lead_ids": declared_lead_ids,
            "unit_by_id": {str(target["target_id"]): target for target in units},
            "lead_by_id": {str(target["target_id"]): target for target in leads},
        },
        issues,
    )


def _portable_atomic_gap_index(
    draft: object,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, object]]]:
    if not isinstance(draft, _PortableDraft) or not isinstance(draft.get("gaps"), list):
        return {}, [
            _atomic_issue("COVERAGE_GAP_INVALID", "The authored gap ledger is malformed.")
        ]
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    gaps: list[_PortableGap] = []
    for index, gap in enumerate(draft["gaps"]):
        gap_code: object = None
        try:
            if not isinstance(gap, _PortableGap):
                raise TypeError
            raw_code = gap.get("code")
            if isinstance(raw_code, str) and raw_code.strip():
                gap_code = raw_code
            gaps.append(_draft_gap(dict(gap), f"draft.gaps[{index}]"))
        except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_GAP_INVALID",
                "The authored gap ledger contains a malformed row.",
                gap_code,
            )
            continue
    counts = Counter(str(gap["code"]) for gap in gaps)
    for gap_code, count in sorted(counts.items()):
        if count > 1:
            _append_atomic_issue(
                issues,
                issue_keys,
                "COVERAGE_GAP_INVALID",
                "Authored gaps contain a duplicate mapping code.",
                gap_code,
            )
    return (
        {
            str(gap["code"]): {
                "code": gap["code"],
                "category": gap["category"],
                "source_ids": tuple(gap["source_ids"]),
            }
            for gap in gaps
            if counts[str(gap["code"])] == 1
        },
        issues,
    )


def _portable_atomic_claim_index(
    draft: dict[str, Any],
    sources: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, object]]]:
    issues: list[dict[str, Any]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    brief = draft.get("brief")
    try:
        if brief is not None:
            if not isinstance(brief, _PortableBrief):
                raise TypeError
            _brief(dict(brief), "draft.brief")
    except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
        _append_proposition_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The analysis draft could not be reconciled into exact evidence.",
        )
        return {}, cast(list[dict[str, object]], issues)
    claims, _ = _portable_proposition_claim_index(
        draft,
        sources,
        issues=issues,
        issue_keys=issue_keys,
    )
    return claims, cast(list[dict[str, object]], issues)


def _portable_atomic_brief_bindings(brief: object) -> dict[str, dict[str, list[str]]]:
    locations: dict[str, dict[str, list[str]]] = {
        "claim": defaultdict(list),
        "atom": defaultdict(list),
        "relationship": defaultdict(list),
    }
    if brief is not None and not isinstance(brief, _PortableBrief):
        return {label: {} for label in locations}

    def add_bindings(binding: object, path: str) -> None:
        if not isinstance(binding, dict):
            return
        for label, field_name in (
            ("claim", "claim_ids"),
            ("atom", "atom_ids"),
            ("relationship", "relationship_ids"),
        ):
            values = binding.get(field_name)
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not item.strip() for item in values
            ):
                continue
            for identifier in values:
                if path not in locations[label][identifier]:
                    locations[label][identifier].append(path)

    def walk_block(block: object, path: str) -> None:
        if not isinstance(block, dict) or block.get("purpose") != "legal_analysis":
            return
        if block.get("kind") == "paragraph":
            add_bindings(block, path)
        elif block.get("kind") in {"bullet_list", "numbered_list"}:
            items = block.get("items")
            if isinstance(items, list):
                for index, item in enumerate(items):
                    add_bindings(item, f"{path}.items[{index}]")
        elif block.get("kind") == "table":
            rows = block.get("rows")
            if isinstance(rows, list):
                for index, row in enumerate(rows):
                    add_bindings(row, f"{path}.rows[{index}]")

    if isinstance(brief, dict):
        summary = brief.get("executive_summary")
        if isinstance(summary, list):
            for block_index, block in enumerate(summary):
                walk_block(block, f"brief.executive_summary[{block_index}]")
        sections = brief.get("sections")
        if isinstance(sections, list):
            for section_index, section in enumerate(sections):
                if not isinstance(section, dict):
                    continue
                section_path = f"brief.sections[{section_index}]"
                blocks = section.get("blocks")
                if isinstance(blocks, list):
                    for block_index, block in enumerate(blocks):
                        walk_block(block, f"{section_path}.blocks[{block_index}]")
                subsections = section.get("subsections")
                if not isinstance(subsections, list):
                    continue
                for subsection_index, subsection in enumerate(subsections):
                    if not isinstance(subsection, dict):
                        continue
                    subsection_blocks = subsection.get("blocks")
                    if not isinstance(subsection_blocks, list):
                        continue
                    for block_index, block in enumerate(subsection_blocks):
                        walk_block(
                            block,
                            f"{section_path}.subsections[{subsection_index}]"
                            f".blocks[{block_index}]",
                        )
    return {
        label: {
            identifier: sorted(paths)
            for identifier, paths in sorted(values.items())
        }
        for label, values in locations.items()
    }


def _portable_atomic_span_overlaps(
    span: dict[str, Any], target: dict[str, Any]
) -> bool:
    return (
        span["source_id"] == target["source_id"]
        and span["start_char"] < target["end_char"]
        and target["start_char"] < span["end_char"]
    )


def _portable_atomic_extend_issues(
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    incoming: list[dict[str, object]],
    *,
    code: str,
) -> None:
    for issue in incoming:
        message = issue.get("message")
        related_ids = issue.get("related_ids")
        _append_atomic_issue(
            issues,
            issue_keys,
            code,
            message if isinstance(message, str) else "A shared coverage index is malformed.",
            *(related_ids if isinstance(related_ids, list) else []),
        )


def _portable_atomic_validated_rows(
    value: object,
    row_type: type[dict[str, Any]],
    parser: Any,
    *,
    label: str,
    identifier_field: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    invalid_identifiers: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _append_atomic_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            f"The atomic {label} collection is malformed.",
        )
        return []
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        identifier = row.get(identifier_field) if isinstance(row, dict) else None
        try:
            if not isinstance(row, row_type):
                raise TypeError
            rows.append(parser(dict(row), f"draft.{label.replace(' ', '_')}[{index}]"))
        except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
            _append_atomic_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                f"The atomic {label} collection contains a malformed row.",
                identifier,
            )
            if (
                invalid_identifiers is not None
                and isinstance(identifier, str)
                and identifier.strip()
            ):
                invalid_identifiers.add(identifier)
    return rows


def _portable_atomic_unique_rows(
    rows: list[dict[str, Any]],
    *,
    identifier_field: str,
    label: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> dict[str, dict[str, Any]]:
    identifiers = [str(row[identifier_field]) for row in rows]
    counts = Counter(identifiers)
    for identifier, count in sorted(counts.items()):
        if count > 1:
            _append_atomic_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                f"Atomic {label} identifiers must be unique.",
                identifier,
            )
    return {
        identifier: row
        for identifier, row in sorted(
            zip(identifiers, rows, strict=True), key=lambda item: item[0]
        )
        if counts[identifier] == 1
    }


def _portable_atomic_invalid_targets(
    objects: list[dict[str, Any]],
    *,
    identifier_field: str,
    valid_ids: set[str],
) -> list[dict[str, Any]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    for item in objects:
        target_id = item.get(identifier_field)
        if not isinstance(target_id, str) or not target_id.strip() or target_id in valid_ids:
            continue
        candidate = {
            "target_id": target_id,
            "source_id": item.get("source_id")
            if isinstance(item.get("source_id"), str) and str(item["source_id"]).strip()
            else None,
            "start_char": item.get("start_char")
            if _proposition_is_int(item.get("start_char"))
            else None,
            "end_char": item.get("end_char")
            if _proposition_is_int(item.get("end_char"))
            else None,
            "category": item.get("issue_category")
            if isinstance(item.get("issue_category"), str)
            and str(item["issue_category"]).strip()
            else None,
            "review_required": item.get("review_required")
            if isinstance(item.get("review_required"), bool)
            else None,
        }
        candidates.setdefault(target_id, []).append(candidate)

    def candidate_key(target: dict[str, Any]) -> tuple[object, ...]:
        return (
            target["source_id"] is None,
            target["source_id"] or "",
            target["start_char"] is None,
            target["start_char"] if target["start_char"] is not None else -1,
            target["end_char"] is None,
            target["end_char"] if target["end_char"] is not None else -1,
            target["category"] is None,
            target["category"] or "",
            target["review_required"] is None,
            target["review_required"] is True,
        )

    return [
        min(rows, key=candidate_key) for _, rows in sorted(candidates.items())
    ]


def _portable_atomic_metadata_equal(value: object, expected: object) -> bool:
    if isinstance(expected, int):
        return _proposition_is_int(value) and value == expected
    if isinstance(expected, str):
        return isinstance(value, str) and value == expected
    return (
        isinstance(expected, dict)
        and isinstance(value, dict)
        and all(isinstance(key, str) and key.strip() for key in value)
        and all(_proposition_is_int(count) for count in value.values())
        and value == expected
    )


def _portable_atomic_validate_inventory_metadata(
    source_unit_inventory: dict[str, Any],
    evidence_inventory: dict[str, Any],
    targets: dict[str, Any],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    eligible_source_count = sum(
        source.get("fetch_status", "succeeded") == "succeeded"
        and source.get("source_role") != "commentary_analysis"
        and source.get("source_quality", "unknown") != "unusable"
        for source in targets["source_by_id"].values()
    )
    evidence_source_count = sum(
        source.get("fetch_status", "succeeded") == "succeeded"
        and bool(source.get("normalized_text"))
        for source in targets["source_by_id"].values()
    )
    topic_counts: Counter[str] = Counter()
    priority_topic_counts: Counter[str] = Counter()
    priority_lead_count = 0
    for lead in targets["lead_objects"]:
        topic = lead.get("topic")
        if isinstance(topic, str) and topic.strip():
            topic_counts[topic] += 1
            if lead.get("review_required") is True:
                priority_topic_counts[topic] += 1
        if lead.get("review_required") is True:
            priority_lead_count += 1
    expectations = (
        (source_unit_inventory, "eligible_source_count", eligible_source_count,
         "Prepared source-unit inventory metadata is inconsistent."),
        (evidence_inventory, "source_count", evidence_source_count,
         "Prepared provision-lead inventory metadata is inconsistent."),
        (evidence_inventory, "priority_lead_count", priority_lead_count,
         "Prepared provision-lead inventory metadata is inconsistent."),
        (evidence_inventory, "priority_topic_counts", dict(sorted(priority_topic_counts.items())),
         "Prepared provision-lead inventory metadata is inconsistent."),
        (evidence_inventory, "priority_cap_per_topic", MAX_PRIORITY_LEADS_PER_TOPIC,
         "Prepared provision-lead inventory metadata is inconsistent."),
        (evidence_inventory, "topic_counts", dict(sorted(topic_counts.items())),
         "Prepared provision-lead inventory metadata is inconsistent."),
        (evidence_inventory, "notice", PROVISION_LEADS_NOTICE,
         "Prepared provision-lead inventory metadata is inconsistent."),
    )
    for inventory, field_name, expected, message in expectations:
        if not _portable_atomic_metadata_equal(inventory.get(field_name), expected):
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_REVIEW_INVALID", message, field_name
            )
    if any(count > MAX_PRIORITY_LEADS_PER_TOPIC for count in priority_topic_counts.values()):
        _append_atomic_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "Prepared provision-lead inventory metadata is inconsistent.",
            "priority_cap_per_topic",
        )


def _evaluate_portable_atomic_target_review(
    source_unit_inventory: object,
    evidence_inventory: object,
    draft: object,
    sources: object,
) -> dict[str, object]:
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    safe_units = source_unit_inventory if isinstance(source_unit_inventory, dict) else {}
    safe_leads = evidence_inventory if isinstance(evidence_inventory, dict) else {}
    if not isinstance(source_unit_inventory, dict):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The prepared source-unit inventory is malformed."
        )
    if not isinstance(evidence_inventory, dict):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The prepared provision-lead inventory is malformed."
        )
    unit_version = safe_units.get("inventory_version")
    lead_version = safe_leads.get("inventory_version")
    if unit_version != SOURCE_UNIT_INVENTORY_VERSION:
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The prepared source-unit inventory version is missing or mismatched."
        )
    if lead_version != PROVISION_LEADS_VERSION:
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The prepared provision-lead inventory version is missing or mismatched."
        )
    try:
        targets, target_issues = _portable_atomic_target_indexes(
            safe_units, safe_leads, sources
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        targets = {
            "source_by_id": {}, "unit_objects": [], "lead_objects": [],
            "units": [], "leads": [], "declared_unit_ids": set(),
            "declared_lead_ids": set(), "unit_by_id": {}, "lead_by_id": {},
        }
        target_issues = []
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The prepared target inventories could not be indexed safely."
        )
    _portable_atomic_extend_issues(
        issues, issue_keys, target_issues, code="ATOMIC_REVIEW_INVALID"
    )
    _portable_atomic_validate_inventory_metadata(
        safe_units, safe_leads, targets, issues=issues, issue_keys=issue_keys
    )
    invalid_units = _portable_atomic_invalid_targets(
        targets["unit_objects"],
        identifier_field="unit_id",
        valid_ids=set(targets["unit_by_id"]),
    )
    invalid_leads = _portable_atomic_invalid_targets(
        targets["lead_objects"],
        identifier_field="lead_id",
        valid_ids=set(targets["lead_by_id"]),
    )
    if not isinstance(draft, _PortableDraft):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
            "The atomic analysis draft is malformed."
        )
        unit_review_value: object = None
        lead_review_value: object = None
        atom_value: object = None
        gap_by_code: dict[str, dict[str, Any]] = {}
    else:
        if draft.get("coverage_contract_version") != ATOMIC_COVERAGE_CONTRACT_VERSION:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_REVIEW_INVALID",
                "The draft atomic coverage contract is missing or mismatched."
            )
        if draft.get("coverage_contract_version") == (
            ATOMIC_COVERAGE_CONTRACT_VERSION
        ) and not (
            isinstance(draft.get("lead_reviews"), list)
            and not draft["lead_reviews"]
            and isinstance(draft.get("proposition_coverage"), list)
            and not draft["proposition_coverage"]
        ):
            _append_atomic_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                "A proposition-coverage-v2 draft cannot include legacy "
                "lead_reviews or proposition_coverage rows.",
            )
        unit_review_value = draft.get("unit_reviews", [])
        lead_review_value = draft.get("lead_dispositions_v2", [])
        atom_value = draft.get("rule_atoms", [])
        try:
            gap_by_code, gap_issues = _portable_atomic_gap_index(draft)
        except (AttributeError, KeyError, TypeError, ValueError):
            gap_by_code, gap_issues = {}, []
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_GAP_INVALID",
                "The authored atomic gap ledger could not be indexed safely."
            )
        _portable_atomic_extend_issues(
            issues, issue_keys, gap_issues, code="ATOMIC_GAP_INVALID"
        )
    unit_reviews = _portable_atomic_validated_rows(
        unit_review_value, _PortableUnitReview, _atomic_unit_review,
        label="unit review", identifier_field="unit_id",
        issues=issues, issue_keys=issue_keys,
    )
    lead_reviews = _portable_atomic_validated_rows(
        lead_review_value, _PortableLeadDisposition, _atomic_lead_disposition,
        label="lead disposition", identifier_field="lead_id",
        issues=issues, issue_keys=issue_keys,
    )
    invalid_atom_ids: set[str] = set()
    atoms = _portable_atomic_validated_rows(
        atom_value, _PortableRuleAtom, _atomic_rule_atom,
        label="rule atom", identifier_field="atom_id",
        issues=issues, issue_keys=issue_keys,
        invalid_identifiers=invalid_atom_ids,
    )
    unit_review_by_id = _portable_atomic_unique_rows(
        unit_reviews, identifier_field="unit_id", label="unit review",
        issues=issues, issue_keys=issue_keys,
    )
    lead_review_by_id = _portable_atomic_unique_rows(
        lead_reviews, identifier_field="lead_id", label="lead disposition",
        issues=issues, issue_keys=issue_keys,
    )
    atom_by_id = _portable_atomic_unique_rows(
        atoms, identifier_field="atom_id", label="rule atom",
        issues=issues, issue_keys=issue_keys,
    )
    invalid_atom_ids.update(
        identifier
        for identifier, count in Counter(atom["atom_id"] for atom in atoms).items()
        if count > 1
    )
    invalid_unit_atom_refs: set[tuple[str, str]] = set()
    invalid_lead_atom_refs: set[str] = set()
    for unit_id in sorted(unit_review_by_id):
        if unit_id not in targets["declared_unit_ids"]:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_TARGET_UNKNOWN",
                "A unit review references a unit outside the prepared inventory.", unit_id
            )
    for lead_id in sorted(lead_review_by_id):
        if lead_id not in targets["declared_lead_ids"]:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_TARGET_UNKNOWN",
                "A lead disposition references a lead outside the prepared inventory.", lead_id
            )
    for atom_id, atom in atom_by_id.items():
        for unit_id in atom["unit_ids"]:
            if unit_id not in targets["declared_unit_ids"]:
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_TARGET_UNKNOWN",
                    "A rule atom references a unit outside the prepared inventory.",
                    atom_id, unit_id,
                )
        for lead_id in atom["lead_ids"]:
            if lead_id not in targets["declared_lead_ids"]:
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_TARGET_UNKNOWN",
                    "A rule atom references a lead outside the prepared inventory.",
                    atom_id, lead_id,
                )
    for target in targets["units"]:
        target_id = str(target["target_id"])
        review = unit_review_by_id.get(target_id)
        if review is None:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_UNIT_REVIEW_UNRESOLVED",
                "Required source unit has no complete nine-dimension review.", target_id
            )
            continue
        for dimension_name in _ATOMIC_DIMENSION_NAMES:
            dimension = review["dimensions"][dimension_name]
            if dimension["disposition"] == "mapped":
                for atom_id in dimension["atom_ids"]:
                    mapped_atom = atom_by_id.get(atom_id)
                    if mapped_atom is None and atom_id in invalid_atom_ids:
                        invalid_unit_atom_refs.add((target_id, dimension_name))
                    elif mapped_atom is None or target_id not in mapped_atom["unit_ids"]:
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_REVIEW_INVALID",
                            "A mapped unit dimension lacks a reciprocal rule-atom target.",
                            target_id, dimension_name, atom_id,
                        )
            elif dimension["disposition"] == "gap":
                for gap_code in dimension["gap_codes"]:
                    gap = gap_by_code.get(gap_code)
                    source_ids = gap.get("source_ids", ()) if gap is not None else ()
                    if (
                        gap is None
                        or len(source_ids) != len(set(source_ids))
                        or set(source_ids) != {target["source_id"]}
                    ):
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_GAP_INVALID",
                            "A unit-dimension gap must be unique, authored, and source-bound.",
                            target_id, dimension_name, gap_code,
                        )
    for target in targets["leads"]:
        target_id = str(target["target_id"])
        review = lead_review_by_id.get(target_id)
        if review is None:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_LEAD_REVIEW_UNRESOLVED",
                "Provision lead has no atomic disposition.", target_id
            )
            continue
        if review["disposition"] == "mapped":
            for atom_id in review["atom_ids"]:
                mapped_atom = atom_by_id.get(atom_id)
                if mapped_atom is None and atom_id in invalid_atom_ids:
                    invalid_lead_atom_refs.add(target_id)
                elif mapped_atom is None or target_id not in mapped_atom["lead_ids"]:
                    _append_atomic_issue(
                        issues, issue_keys, "ATOMIC_REVIEW_INVALID",
                        "A mapped lead disposition lacks a reciprocal rule-atom target.",
                        target_id, atom_id,
                    )
        elif review["disposition"] == "gap":
            for gap_code in review["gap_codes"]:
                gap = gap_by_code.get(gap_code)
                source_ids = gap.get("source_ids", ()) if gap is not None else ()
                if (
                    gap is None
                    or len(source_ids) != len(set(source_ids))
                    or set(source_ids) != {target["source_id"]}
                    or gap.get("category") != target["category"]
                ):
                    _append_atomic_issue(
                        issues, issue_keys, "ATOMIC_GAP_INVALID",
                        "A lead gap must be unique, authored, source-bound, and category-matched.",
                        target_id, gap_code,
                    )
    for atom_id, atom in atom_by_id.items():
        for unit_id in atom["unit_ids"]:
            review = unit_review_by_id.get(unit_id)
            reciprocal = review is not None and any(
                review["dimensions"][name]["disposition"] == "mapped"
                and atom_id in review["dimensions"][name]["atom_ids"]
                for name in _ATOMIC_DIMENSION_NAMES
            )
            if not reciprocal and unit_id in targets["unit_by_id"]:
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_REVIEW_INVALID",
                    "A rule atom unit target lacks a reciprocal mapped dimension.",
                    atom_id, unit_id,
                )
        for lead_id in atom["lead_ids"]:
            review = lead_review_by_id.get(lead_id)
            reciprocal = (
                review is not None
                and review["disposition"] == "mapped"
                and atom_id in review["atom_ids"]
            )
            if not reciprocal and lead_id in targets["lead_by_id"]:
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_REVIEW_INVALID",
                    "A rule atom lead target lacks a reciprocal mapped disposition.",
                    atom_id, lead_id,
                )
    issues.sort(
        key=lambda issue: (
            str(issue["code"]), _atomic_issue_sort_ids(issue), str(issue["message"])
        )
    )
    unit_results: list[dict[str, object]] = []
    unit_dispositions: Counter[str] = Counter()
    for target in sorted(
        targets["units"],
        key=lambda item: (
            item["source_id"], item["start_char"], item["end_char"], item["target_id"]
        ),
    ):
        target_id = str(target["target_id"])
        review = unit_review_by_id.get(target_id)
        unit_valid = review is not None and not _atomic_related_issue(issues, target_id)
        dimensions: dict[str, object] = {}
        for dimension_name in _ATOMIC_DIMENSION_NAMES:
            if review is None:
                disposition, atom_ids, gap_codes, rationale, dimension_valid = (
                    "unresolved", [], [], None, False
                )
            else:
                dimension = review["dimensions"][dimension_name]
                disposition = dimension["disposition"]
                atom_ids = sorted(dimension["atom_ids"])
                gap_codes = sorted(dimension["gap_codes"])
                rationale = dimension["rationale"]
                dimension_valid = not any(
                    _atomic_issue_has_related_ids(issue, target_id, dimension_name)
                    for issue in issues
                ) and (target_id, dimension_name) not in invalid_unit_atom_refs
            unit_dispositions[str(disposition)] += 1
            dimensions[dimension_name] = {
                "disposition": disposition,
                "atom_ids": atom_ids,
                "gap_codes": gap_codes,
                "rationale": rationale,
                "valid": dimension_valid,
            }
            unit_valid = unit_valid and bool(dimension_valid)
        unit_results.append(
            {
                "unit_id": target_id,
                "source_id": target["source_id"],
                "target_state": "valid",
                "dimensions": dimensions,
                "valid": unit_valid,
            }
        )
    for target in invalid_units:
        unit_dispositions["invalid"] += len(_ATOMIC_DIMENSION_NAMES)
        unit_results.append(
            {
                "unit_id": target["target_id"],
                "source_id": target["source_id"],
                "target_state": "invalid",
                "dimensions": {
                    name: {
                        "disposition": "invalid", "atom_ids": [], "gap_codes": [],
                        "rationale": None, "valid": False,
                    }
                    for name in _ATOMIC_DIMENSION_NAMES
                },
                "valid": False,
            }
        )
    unit_order = {
        str(target["target_id"]): (
            target["source_id"], target["start_char"], target["end_char"],
            target["target_id"],
        )
        for target in targets["units"]
    }
    unit_order.update(
        {
            str(target["target_id"]): (
                target["source_id"] or "",
                target["start_char"] if target["start_char"] is not None else -1,
                target["end_char"] if target["end_char"] is not None else -1,
                target["target_id"],
            )
            for target in invalid_units
        }
    )
    unit_results.sort(key=lambda row: unit_order[str(row["unit_id"])])
    lead_priority = {
        str(item["lead_id"]): item.get("review_required")
        for item in targets["lead_objects"]
        if isinstance(item.get("lead_id"), str)
        and str(item["lead_id"]) in targets["lead_by_id"]
    }
    lead_results: list[dict[str, object]] = []
    lead_dispositions: Counter[str] = Counter()
    for target in sorted(
        targets["leads"],
        key=lambda item: (
            item["source_id"], item["start_char"], item["end_char"], item["target_id"]
        ),
    ):
        target_id = str(target["target_id"])
        review = lead_review_by_id.get(target_id)
        if review is None:
            disposition, atom_ids, gap_codes, rationale = "unresolved", [], [], None
        else:
            disposition = review["disposition"]
            atom_ids = sorted(review["atom_ids"])
            gap_codes = sorted(review["gap_codes"])
            rationale = review["rationale"]
        lead_dispositions[str(disposition)] += 1
        lead_results.append(
            {
                "lead_id": target_id,
                "source_id": target["source_id"],
                "target_state": "valid",
                "issue_category": target["category"],
                "review_required": lead_priority.get(target_id),
                "disposition": disposition,
                "atom_ids": atom_ids,
                "gap_codes": gap_codes,
                "rationale": rationale,
                "valid": review is not None
                and target_id not in invalid_lead_atom_refs
                and not _atomic_related_issue(issues, target_id),
            }
        )
    for target in invalid_leads:
        lead_dispositions["invalid"] += 1
        lead_results.append(
            {
                "lead_id": target["target_id"], "source_id": target["source_id"],
                "target_state": "invalid", "issue_category": target["category"],
                "review_required": target["review_required"], "disposition": "invalid",
                "atom_ids": [], "gap_codes": [], "rationale": None, "valid": False,
            }
        )
    lead_order = {
        str(target["target_id"]): (
            target["source_id"], target["start_char"], target["end_char"],
            target["target_id"],
        )
        for target in targets["leads"]
    }
    lead_order.update(
        {
            str(target["target_id"]): (
                target["source_id"] or "",
                target["start_char"] if target["start_char"] is not None else -1,
                target["end_char"] if target["end_char"] is not None else -1,
                target["target_id"],
            )
            for target in invalid_leads
        }
    )
    lead_results.sort(key=lambda row: lead_order[str(row["lead_id"])])
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "inventory_versions": {
            "provision_leads": lead_version if isinstance(lead_version, str) else None,
            "source_units": unit_version if isinstance(unit_version, str) else None,
        },
        "valid": not issues,
        "target_counts": {
            "invalid_leads": len(invalid_leads), "invalid_units": len(invalid_units),
            "lead_rows": len(targets["lead_objects"]), "leads": len(lead_results),
            "unit_rows": len(targets["unit_objects"]), "units": len(unit_results),
        },
        "disposition_counts": {
            "lead_dispositions": {
                value: lead_dispositions[value]
                for value in ("gap", "invalid", "mapped", "not_material", "unresolved")
            },
            "unit_dimensions": {
                value: unit_dispositions[value]
                for value in (
                    "gap", "invalid", "mapped", "not_material", "not_present", "unresolved"
                )
            },
        },
        "units": unit_results,
        "leads": lead_results,
        "issues": issues,
    }
    payload["target_review_hash"] = _sha256(_canonical_bytes(payload))
    return payload


def _portable_atomic_graph_rows(
    value: object,
    row_type: type[dict[str, Any]],
    parser: Any,
    *,
    identifier_field: str,
    label: str,
    issue_code: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[int, dict[str, dict[str, Any]], set[str]]:
    if not isinstance(value, list):
        _append_atomic_issue(
            issues,
            issue_keys,
            issue_code,
            f"The atomic {label} collection is malformed.",
        )
        return 0, {}, set()
    candidates: dict[str, list[dict[str, Any] | None]] = {}
    for index, row in enumerate(value):
        payload = row if isinstance(row, dict) else {}
        raw_identifier = payload.get(identifier_field)
        identifier = (
            raw_identifier
            if isinstance(raw_identifier, str) and raw_identifier.strip()
            else None
        )
        try:
            if not isinstance(row, row_type):
                raise TypeError
            validated = parser(dict(row), f"draft.{label.replace(' ', '_')}[{index}]")
        except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
            _append_atomic_issue(
                issues,
                issue_keys,
                issue_code,
                f"The atomic {label} collection contains a malformed row.",
                identifier,
            )
            if identifier is not None:
                candidates.setdefault(identifier, []).append(None)
            continue
        candidates.setdefault(str(validated[identifier_field]), []).append(validated)
    valid_by_id: dict[str, dict[str, Any]] = {}
    invalid_ids: set[str] = set()
    for identifier, rows in sorted(candidates.items()):
        if len(rows) != 1:
            _append_atomic_issue(
                issues,
                issue_keys,
                issue_code,
                f"Atomic {label} identifiers must be unique.",
                identifier,
            )
            invalid_ids.add(identifier)
        elif rows[0] is None:
            invalid_ids.add(identifier)
        else:
            valid_by_id[identifier] = cast(dict[str, Any], rows[0])
    return len(value), valid_by_id, invalid_ids


def _portable_atomic_relationship_categories_valid(
    relationship: dict[str, Any], source: dict[str, Any], target: dict[str, Any]
) -> bool:
    relation_type = relationship["relation_type"]
    source_type = source["proposition_type"]
    target_type = target["proposition_type"]
    requirement_like = target_type in {
        "duty", "prohibition", "right", "scope", "implementation", "other"
    } or target["category"] == "requirements"
    if relation_type == "qualifies":
        return source_type in {"status", "scope", "other"}
    if relation_type == "exception_to":
        return source_type == "exception" and requirement_like
    if relation_type == "deadline_for":
        return source_type == "deadline" and target_type not in {
            "status", "definition", "deadline"
        }
    if relation_type == "enforces":
        return source_type == "enforcement_route" and requirement_like
    if relation_type == "triggered_by":
        return (
            source_type == "enforcement_trigger"
            and target_type in {"duty", "prohibition"}
        ) or (
            source_type in {"remedy", "penalty"}
            and target_type == "enforcement_trigger"
        )
    if relation_type == "consequence_of":
        return source_type in {"remedy", "penalty"} and target_type in {
            "duty", "prohibition"
        }
    if relation_type == "appeals_from":
        return source_type == "appeal" and target_type in {
            "enforcement_route", "remedy", "penalty"
        }
    return relation_type == "defines" and source_type == "definition"


def _portable_atomic_cyclic_components(
    relationships: list[dict[str, Any]],
) -> tuple[frozenset[str], ...]:
    adjacency: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for relationship in relationships:
        if relationship["relation_type"] not in _ATOMIC_ACYCLIC_RELATIONSHIPS:
            continue
        source_id = relationship["source_atom_id"]
        target_id = relationship["target_atom_id"]
        adjacency.setdefault(source_id, set()).add(target_id)
        adjacency.setdefault(target_id, set())
        reverse.setdefault(target_id, set()).add(source_id)
        reverse.setdefault(source_id, set())
    visited: set[str] = set()
    finish_order: list[str] = []
    for root in sorted(adjacency):
        if root in visited:
            continue
        visited.add(root)
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            stack.append((node, True))
            for neighbor in sorted(adjacency[node], reverse=True):
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append((neighbor, False))
    components: list[frozenset[str]] = []
    assigned: set[str] = set()
    for root in reversed(finish_order):
        if root in assigned:
            continue
        component: set[str] = set()
        stack = [root]
        assigned.add(root)
        while stack:
            node = stack.pop()
            component.add(node)
            for neighbor in sorted(reverse[node], reverse=True):
                if neighbor not in assigned:
                    assigned.add(neighbor)
                    stack.append(neighbor)
        if len(component) > 1:
            components.append(frozenset(component))
    return tuple(sorted(components, key=lambda value: tuple(sorted(value))))


def _evaluate_portable_atomic_rule_graph(draft: object) -> dict[str, object]:
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    if not isinstance(draft, _PortableDraft):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_RULE_INVALID",
            "The atomic analysis draft is malformed."
        )
        atom_value: object = None
        relationship_value: object = None
    else:
        if draft.get("coverage_contract_version") != ATOMIC_COVERAGE_CONTRACT_VERSION:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_RULE_INVALID",
                "The draft atomic coverage contract is missing or mismatched."
            )
        atom_value = draft.get("rule_atoms", [])
        relationship_value = draft.get("rule_relationships", [])
    atom_count, atoms, invalid_atom_ids = _portable_atomic_graph_rows(
        atom_value, _PortableRuleAtom, _atomic_rule_atom,
        identifier_field="atom_id", label="rule atom",
        issue_code="ATOMIC_RULE_INVALID", issues=issues, issue_keys=issue_keys,
    )
    relationship_count, relationships, invalid_relationship_ids = (
        _portable_atomic_graph_rows(
            relationship_value, _PortableRuleRelationship,
            _atomic_rule_relationship, identifier_field="relationship_id",
            label="rule relationship", issue_code="ATOMIC_RELATIONSHIP_INVALID",
            issues=issues, issue_keys=issue_keys,
        )
    )
    declared_atom_ids = set(atoms) | invalid_atom_ids
    for atom_id, atom in atoms.items():
        for element_name in _ATOMIC_REQUIRED_ELEMENTS[atom["proposition_type"]]:
            if atom["elements"][element_name]["status"] == "stated":
                continue
            invalid_atom_ids.add(atom_id)
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_REQUIRED_ELEMENT_MISSING",
                "A rule atom is missing a required stated element.",
                atom_id, element_name,
            )
    category_valid_relationship_ids: set[str] = set()
    cycle_candidates: list[dict[str, Any]] = []
    for relationship_id, relationship in relationships.items():
        unknown_ids = sorted(
            endpoint for endpoint in {
                relationship["source_atom_id"], relationship["target_atom_id"]
            } if endpoint not in declared_atom_ids
        )
        if unknown_ids:
            invalid_relationship_ids.add(relationship_id)
            for unknown_id in unknown_ids:
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_RELATIONSHIP_UNKNOWN",
                    "A rule relationship references an unknown atom.", unknown_id,
                )
            continue
        source = atoms.get(relationship["source_atom_id"])
        target = atoms.get(relationship["target_atom_id"])
        if source is None or target is None:
            invalid_relationship_ids.add(relationship_id)
            continue
        if not _portable_atomic_relationship_categories_valid(
            relationship, source, target
        ):
            invalid_relationship_ids.add(relationship_id)
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_RELATIONSHIP_INVALID",
                "A rule relationship has an invalid direction or endpoint category.",
                relationship_id, relationship["source_atom_id"],
                relationship["target_atom_id"],
            )
        else:
            category_valid_relationship_ids.add(relationship_id)
            if relationship["relation_type"] in _ATOMIC_ACYCLIC_RELATIONSHIPS:
                cycle_candidates.append(relationship)
    for component in _portable_atomic_cyclic_components(cycle_candidates):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_RELATIONSHIP_INVALID",
            "Atomic rule relationships contain a prohibited cycle.", *component,
        )
        for relationship_id, relationship in relationships.items():
            if (
                relationship["relation_type"] in _ATOMIC_ACYCLIC_RELATIONSHIPS
                and relationship["source_atom_id"] in component
                and relationship["target_atom_id"] in component
            ):
                invalid_relationship_ids.add(relationship_id)
    outgoing_types: dict[str, set[str]] = {}
    for relationship_id in sorted(category_valid_relationship_ids):
        relationship = relationships[relationship_id]
        outgoing_types.setdefault(relationship["source_atom_id"], set()).add(
            relationship["relation_type"]
        )
    for atom_id, atom in atoms.items():
        if atom_id in invalid_atom_ids:
            continue
        alternatives = _ATOMIC_REQUIRED_RELATIONSHIPS.get(
            atom["proposition_type"], ()
        )
        if alternatives and not outgoing_types.get(atom_id, set()).intersection(
            alternatives
        ):
            invalid_atom_ids.add(atom_id)
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_RELATIONSHIP_REQUIRED",
                "A rule atom is missing a required valid outgoing relationship.",
                atom_id,
            )
    issues.sort(
        key=lambda issue: (
            str(issue["code"]), _atomic_issue_sort_ids(issue), str(issue["message"])
        )
    )
    atom_results: list[dict[str, object]] = []
    for atom_id in sorted(declared_atom_ids):
        atom = atoms.get(atom_id)
        if atom is None:
            atom_results.append(
                {"atom_id": atom_id, "row_state": "invalid", "category": None,
                 "proposition_type": None, "materiality": None, "unit_ids": [],
                 "lead_ids": [], "required_elements": [], "stated_elements": [],
                 "required_relationship_types": [], "valid": False}
            )
            continue
        atom_results.append(
            {"atom_id": atom_id, "row_state": "valid",
             "category": atom["category"],
             "proposition_type": atom["proposition_type"],
             "materiality": atom["materiality"],
             "unit_ids": sorted(atom["unit_ids"]),
             "lead_ids": sorted(atom["lead_ids"]),
             "required_elements": sorted(
                 _ATOMIC_REQUIRED_ELEMENTS[atom["proposition_type"]]
             ),
             "stated_elements": sorted(
                 name for name in _ATOMIC_ELEMENT_NAMES
                 if atom["elements"][name]["status"] == "stated"
             ),
             "required_relationship_types": sorted(
                 _ATOMIC_REQUIRED_RELATIONSHIPS.get(atom["proposition_type"], ())
             ),
             "valid": atom_id not in invalid_atom_ids}
        )
    declared_relationship_ids = set(relationships) | invalid_relationship_ids
    relationship_results: list[dict[str, object]] = []
    for relationship_id in sorted(declared_relationship_ids):
        relationship = relationships.get(relationship_id)
        if relationship is None:
            relationship_results.append(
                {"relationship_id": relationship_id, "row_state": "invalid",
                 "relation_type": None, "source_atom_id": None,
                 "target_atom_id": None, "claim_ids": [], "valid": False}
            )
            continue
        relationship_results.append(
            {"relationship_id": relationship_id, "row_state": "valid",
             "relation_type": relationship["relation_type"],
             "source_atom_id": relationship["source_atom_id"],
             "target_atom_id": relationship["target_atom_id"],
             "claim_ids": sorted(relationship["claim_ids"]),
             "valid": relationship_id not in invalid_relationship_ids}
        )
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "valid": not issues,
        "rule_counts": {
            "atom_rows": atom_count,
            "atoms": len(atom_results),
            "invalid_atoms": sum(not bool(row["valid"]) for row in atom_results),
            "relationship_rows": relationship_count,
            "relationships": len(relationship_results),
            "invalid_relationships": sum(
                not bool(row["valid"]) for row in relationship_results
            ),
        },
        "atoms": atom_results,
        "relationships": relationship_results,
        "issues": issues,
    }
    payload["rule_graph_hash"] = _sha256(_canonical_bytes(payload))
    return payload


def _portable_atomic_canonical_issues(
    issues: list[dict[str, object]],
) -> list[dict[str, object]]:
    canonical: list[dict[str, object]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for issue in issues:
        code = issue.get("code")
        message = issue.get("message")
        related_ids = issue.get("related_ids")
        if not isinstance(code, str) or not isinstance(message, str):
            continue
        safe_ids = tuple(
            sorted(
                {
                    identifier
                    for identifier in (
                        related_ids if isinstance(related_ids, list) else []
                    )
                    if isinstance(identifier, str) and identifier.strip()
                }
            )
        )
        key = (code, message, safe_ids)
        if key in seen:
            continue
        seen.add(key)
        canonical.append(
            {"code": code, "message": message, "related_ids": list(safe_ids)}
        )
    canonical.sort(
        key=lambda issue: (
            str(issue["code"]), _atomic_issue_sort_ids(issue), str(issue["message"])
        )
    )
    return canonical


def _portable_atomic_compose(
    target_review: dict[str, object],
    rule_graph: dict[str, object],
    counts: dict[str, int],
    issues: list[dict[str, object]],
) -> dict[str, object]:
    canonical_counts = {
        key: value
        for key, value in sorted(counts.items())
        if isinstance(key, str)
        and key.strip()
        and _proposition_is_int(value)
    }
    canonical_issues = _portable_atomic_canonical_issues(issues)
    payload: dict[str, object] = {
        "schema_version": "3.0",
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "valid": not canonical_issues,
        "target_review": dict(target_review),
        "rule_graph": dict(rule_graph),
        "counts": canonical_counts,
        "issues": canonical_issues,
    }
    payload["coverage_review_hash"] = _sha256(_canonical_bytes(payload))
    return payload


def _portable_atomic_partial_issues(
    review: dict[str, object],
) -> list[dict[str, object]]:
    raw_issues = review.get("issues")
    if not isinstance(raw_issues, list):
        return [
            _atomic_issue(
                "ATOMIC_REVIEW_INVALID",
                "An atomic partial review omitted its canonical diagnostics.",
            )
        ]
    return [issue for issue in raw_issues if isinstance(issue, dict)]


def _portable_atomic_count(value: object) -> int:
    return value if _proposition_is_int(value) else 0


def _portable_atomic_base_counts(
    rule_graph: dict[str, object],
) -> dict[str, int]:
    rule_counts = rule_graph.get("rule_counts")
    safe_rule_counts = rule_counts if isinstance(rule_counts, dict) else {}
    atom_rows = rule_graph.get("atoms")
    materialities: Counter[str] = Counter()
    if isinstance(atom_rows, list):
        materialities.update(
            str(materiality)
            for row in atom_rows
            if isinstance(row, dict)
            and isinstance((materiality := row.get("materiality")), str)
        )
    return {
        "atom_claims": 0,
        "atoms": _portable_atomic_count(safe_rule_counts.get("atoms")),
        "critical_atoms": materialities["critical"],
        "material_atoms": materialities["material"],
        "not_applicable_elements": 0,
        "not_established_elements": 0,
        "relationship_claims": 0,
        "relationships": _portable_atomic_count(
            safe_rule_counts.get("relationships")
        ),
        "stated_elements": 0,
        "supporting_atoms": materialities["supporting"],
        "visible_atoms": 0,
        "visible_relationships": 0,
    }


def _portable_atomic_validated_graph_rows(
    draft: _PortableDraft,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]] | None:
    try:
        atom_rows = draft["rule_atoms"]
        relationship_rows = draft["rule_relationships"]
        if not isinstance(atom_rows, list) or not isinstance(relationship_rows, list):
            return None
        atoms = {
            atom["atom_id"]: _atomic_rule_atom(
                dict(atom), f"draft.rule_atoms[{index}]"
            )
            for index, atom in enumerate(atom_rows)
            if isinstance(atom, _PortableRuleAtom)
        }
        relationships = {
            relationship["relationship_id"]: _atomic_rule_relationship(
                dict(relationship), f"draft.rule_relationships[{index}]"
            )
            for index, relationship in enumerate(relationship_rows)
            if isinstance(relationship, _PortableRuleRelationship)
        }
    except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
        return None
    if len(atoms) != len(atom_rows) or len(relationships) != len(relationship_rows):
        return None
    return atoms, relationships


def _portable_atomic_targets_for_atom(
    atom: dict[str, Any], targets: dict[str, Any]
) -> tuple[dict[str, Any], ...]:
    resolved: list[dict[str, Any]] = []
    for target_id in (*atom["unit_ids"], *atom["lead_ids"]):
        target = targets["unit_by_id"].get(target_id) or targets["lead_by_id"].get(
            target_id
        )
        if target is not None:
            resolved.append(target)
    return tuple(resolved)


def _portable_atomic_validate_atom_evidence(
    atoms: dict[str, dict[str, Any]],
    targets: dict[str, Any],
    claims: dict[str, dict[str, Any]],
    gaps: dict[str, dict[str, Any]],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> set[str]:
    invalid_atom_ids: set[str] = set()
    for atom_id, atom in sorted(atoms.items()):
        assigned_targets = _portable_atomic_targets_for_atom(atom, targets)
        assigned_sources = {target["source_id"] for target in assigned_targets}
        covered_targets: set[str] = set()
        for element_name in _ATOMIC_ELEMENT_NAMES:
            element = atom["elements"][element_name]
            if element["status"] == "stated":
                element_has_exact_evidence = False
                for claim_id in element["claim_ids"]:
                    claim = claims.get(claim_id)
                    if claim is None:
                        invalid_atom_ids.add(atom_id)
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_CLAIM_UNKNOWN",
                            "A stated atom element references an unknown built claim.",
                            atom_id, claim_id,
                        )
                        continue
                    if claim["kind"] != "source_supported":
                        invalid_atom_ids.add(atom_id)
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_CLAIM_NOT_SOURCE_SUPPORTED",
                            (
                                "A stated atom element references a claim that is "
                                "not source-supported."
                            ),
                            atom_id, claim_id,
                        )
                        continue
                    if not claim["spans"]:
                        invalid_atom_ids.add(atom_id)
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                            "A stated atom claim has no resolved exact source evidence.",
                            atom_id, element_name, claim_id,
                        )
                        continue
                    overlapping = {
                        str(target["target_id"])
                        for target in assigned_targets
                        if any(
                            _portable_atomic_span_overlaps(span, target)
                            for span in claim["spans"]
                        )
                    }
                    if not overlapping:
                        invalid_atom_ids.add(atom_id)
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                            "Exact stated-element evidence does not overlap an assigned target.",
                            atom_id, element_name, claim_id,
                        )
                        continue
                    element_has_exact_evidence = True
                    covered_targets.update(overlapping)
                if not element_has_exact_evidence:
                    invalid_atom_ids.add(atom_id)
            elif element["status"] == "not_established":
                covered_gap_sources: set[str] = set()
                for gap_code in element["gap_codes"]:
                    gap = gaps.get(gap_code)
                    source_ids = gap.get("source_ids", ()) if gap is not None else ()
                    if (
                        gap is None
                        or gap.get("category") != atom["category"]
                        or not source_ids
                        or len(source_ids) != len(set(source_ids))
                        or not set(source_ids).issubset(assigned_sources)
                    ):
                        invalid_atom_ids.add(atom_id)
                        _append_atomic_issue(
                            issues, issue_keys, "ATOMIC_GAP_INVALID",
                            "A not-established atom element requires a valid source-tied gap.",
                            atom_id, element_name, gap_code,
                        )
                        continue
                    covered_gap_sources.update(source_ids)
                for source_id in sorted(assigned_sources - covered_gap_sources):
                    invalid_atom_ids.add(atom_id)
                    _append_atomic_issue(
                        issues, issue_keys, "ATOMIC_GAP_INVALID",
                        "A not-established atom element lacks a gap for an assigned source.",
                        atom_id, element_name, source_id,
                    )
        for target in assigned_targets:
            if str(target["target_id"]) in covered_targets:
                continue
            invalid_atom_ids.add(atom_id)
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "Exact atom evidence does not cover an assigned target.",
                atom_id, target["target_id"],
            )
    return invalid_atom_ids


def _portable_atomic_validate_relationship_evidence(
    relationships: dict[str, dict[str, Any]],
    atoms: dict[str, dict[str, Any]],
    targets: dict[str, Any],
    claims: dict[str, dict[str, Any]],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> set[str]:
    invalid_relationship_ids: set[str] = set()
    for relationship_id, relationship in sorted(relationships.items()):
        source_targets = _portable_atomic_targets_for_atom(
            atoms[relationship["source_atom_id"]], targets
        )
        target_targets = _portable_atomic_targets_for_atom(
            atoms[relationship["target_atom_id"]], targets
        )
        for claim_id in relationship["claim_ids"]:
            claim = claims.get(claim_id)
            valid = (
                claim is not None
                and claim["kind"] == "source_supported"
                and bool(claim["spans"])
                and any(
                    _portable_atomic_span_overlaps(span, target)
                    for span in claim["spans"]
                    for target in source_targets
                )
                and any(
                    _portable_atomic_span_overlaps(span, target)
                    for span in claim["spans"]
                    for target in target_targets
                )
            )
            if valid:
                continue
            invalid_relationship_ids.add(relationship_id)
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
                (
                    "A relationship claim requires exact source-supported evidence "
                    "from both endpoint contexts."
                ),
                relationship_id, claim_id,
            )
    return invalid_relationship_ids


def _portable_atomic_bindings_by_location(
    values: dict[str, list[str]],
) -> dict[str, set[str]]:
    by_location: dict[str, set[str]] = {}
    for identifier, locations in values.items():
        for location in locations:
            by_location.setdefault(location, set()).add(identifier)
    return by_location


def _portable_atomic_visibility_requirements(
    atoms: dict[str, dict[str, Any]],
    relationships: dict[str, dict[str, Any]],
    draft: _PortableDraft,
    bindings: dict[str, dict[str, list[str]]],
) -> tuple[set[str], set[str]]:
    base_atoms = {
        atom_id for atom_id, atom in atoms.items()
        if atom["materiality"] in {"critical", "material"}
    }
    for unit_review in draft["unit_reviews"]:
        for dimension_name in _ATOMIC_DIMENSION_NAMES:
            dimension = unit_review["dimensions"][dimension_name]
            if dimension["disposition"] == "mapped":
                base_atoms.update(dimension["atom_ids"])
    required_relationships = set(bindings["relationship"]).intersection(
        relationships
    )
    required_relationships.update(
        relationship_id
        for relationship_id, relationship in relationships.items()
        if {
            relationship["source_atom_id"], relationship["target_atom_id"]
        }.intersection(base_atoms)
    )
    required_atoms = set(base_atoms)
    for relationship_id in required_relationships:
        relationship = relationships[relationship_id]
        required_atoms.update(
            (relationship["source_atom_id"], relationship["target_atom_id"])
        )
    return required_atoms, required_relationships


def _portable_atomic_validate_visibility(
    atoms: dict[str, dict[str, Any]],
    relationships: dict[str, dict[str, Any]],
    draft: _PortableDraft,
    bindings: dict[str, dict[str, list[str]]],
    invalid_evidence_atoms: set[str],
    invalid_evidence_relationships: set[str],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    for atom_id in sorted(set(bindings["atom"]) - set(atoms)):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_BRIEF_BINDING_INVALID",
            "Visible legal analysis references an unknown rule atom.", atom_id,
        )
    for relationship_id in sorted(
        set(bindings["relationship"]) - set(relationships)
    ):
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_BRIEF_BINDING_INVALID",
            "Visible legal analysis references an unknown rule relationship.",
            relationship_id,
        )
    claims_by_location = _portable_atomic_bindings_by_location(bindings["claim"])
    atoms_by_location = _portable_atomic_bindings_by_location(bindings["atom"])
    required_atoms, required_relationships = (
        _portable_atomic_visibility_requirements(
            atoms, relationships, draft, bindings
        )
    )
    visible_atoms = set(bindings["atom"]).intersection(atoms)
    for atom_id in sorted(required_atoms | visible_atoms):
        locations = bindings["atom"].get(atom_id, [])
        if not locations:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_ATOM_NOT_VISIBLE",
                "A visibility-required rule atom is absent from legal analysis.",
                atom_id,
            )
            continue
        if atom_id in invalid_evidence_atoms:
            continue
        required_claims = {
            claim_id
            for element in atoms[atom_id]["elements"].values()
            for claim_id in element["claim_ids"]
        }
        if not any(
            required_claims.issubset(claims_by_location.get(location, set()))
            for location in locations
        ):
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_ATOM_CLAIM_NOT_VISIBLE",
                "A visible rule atom lacks co-bound claims for all stated elements.",
                atom_id,
            )
    for relationship_id in sorted(required_relationships):
        if relationship_id in invalid_evidence_relationships:
            continue
        relationship = relationships[relationship_id]
        if not any(
            relationship["source_atom_id"] in atoms_by_location.get(location, set())
            and relationship["target_atom_id"] in atoms_by_location.get(location, set())
            and bool(
                set(relationship["claim_ids"]).intersection(
                    claims_by_location.get(location, set())
                )
            )
            for location in bindings["relationship"].get(relationship_id, [])
        ):
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_RELATIONSHIP_NOT_VISIBLE",
                (
                    "A material relationship must co-bind both endpoints and an "
                    "evidence claim in one legal-analysis unit."
                ),
                relationship_id, relationship["source_atom_id"],
                relationship["target_atom_id"],
            )


def _portable_atomic_complete_counts(
    counts: dict[str, int],
    atoms: dict[str, dict[str, Any]],
    relationships: dict[str, dict[str, Any]],
    bindings: dict[str, dict[str, list[str]]],
) -> dict[str, int]:
    statuses: Counter[str] = Counter()
    for atom in atoms.values():
        statuses.update(
            atom["elements"][element_name]["status"]
            for element_name in _ATOMIC_ELEMENT_NAMES
        )
    counts.update(
        {
            "atom_claims": len(
                {
                    claim_id
                    for atom in atoms.values()
                    for element in atom["elements"].values()
                    for claim_id in element["claim_ids"]
                }
            ),
            "not_applicable_elements": statuses["not_applicable"],
            "not_established_elements": statuses["not_established"],
            "relationship_claims": len(
                {
                    claim_id
                    for relationship in relationships.values()
                    for claim_id in relationship["claim_ids"]
                }
            ),
            "stated_elements": statuses["stated"],
            "visible_atoms": len(set(bindings["atom"]).intersection(atoms)),
            "visible_relationships": len(
                set(bindings["relationship"]).intersection(relationships)
            ),
        }
    )
    return counts


def _portable_atomic_project_lead_reviews(
    dispositions: object,
) -> list[dict[str, Any]] | None:
    if not isinstance(dispositions, list):
        return None
    projected: dict[str, dict[str, set[str]]] = {}
    for index, disposition in enumerate(dispositions):
        try:
            if not isinstance(disposition, _PortableLeadDisposition):
                return None
            validated = _atomic_lead_disposition(
                dict(disposition), f"draft.lead_dispositions_v2[{index}]"
            )
        except (AttributeError, KeyError, TypeError, ValueError, PortableInputError):
            return None
        state = projected.setdefault(
            validated["lead_id"],
            {"gap_codes": set(), "not_material_rationales": set()},
        )
        if validated["disposition"] == "gap":
            state["gap_codes"].update(validated["gap_codes"])
        elif validated["disposition"] == "not_material":
            if validated["rationale"] is None:
                return None
            state["not_material_rationales"].add(validated["rationale"])
    reviews: list[dict[str, Any]] = []
    for lead_id, state in sorted(projected.items()):
        gap_codes = state["gap_codes"]
        rationales = state["not_material_rationales"]
        if gap_codes:
            reviews.append(
                {"lead_id": lead_id, "disposition": "gap",
                 "gap_codes": sorted(gap_codes),
                 "rationale": "Projected from atomic lead dispositions with gap precedence."}
            )
        elif rationales:
            reviews.append(
                {"lead_id": lead_id, "disposition": "not_material",
                 "gap_codes": [], "rationale": sorted(rationales)[0]}
            )
    return reviews


def _evaluate_portable_atomic_coverage(
    source_unit_inventory: object,
    evidence_inventory: object,
    draft: object,
    sources: object,
) -> dict[str, object]:
    target_review = _evaluate_portable_atomic_target_review(
        source_unit_inventory, evidence_inventory, draft, sources
    )
    rule_graph = _evaluate_portable_atomic_rule_graph(draft)
    counts = _portable_atomic_base_counts(rule_graph)
    partial_issues = [
        *_portable_atomic_partial_issues(target_review),
        *_portable_atomic_partial_issues(rule_graph),
    ]
    if target_review.get("valid") is not True or rule_graph.get("valid") is not True:
        return _portable_atomic_compose(
            target_review, rule_graph, counts, partial_issues
        )
    if not isinstance(draft, _PortableDraft):
        return _portable_atomic_compose(
            target_review, rule_graph, counts,
            [_atomic_issue(
                "ATOMIC_EVIDENCE_INVALID",
                "The validated atomic graph could not be snapshotted safely.",
            )],
        )
    validated_rows = _portable_atomic_validated_graph_rows(draft)
    if validated_rows is None:
        return _portable_atomic_compose(
            target_review, rule_graph, counts,
            [_atomic_issue(
                "ATOMIC_EVIDENCE_INVALID",
                "The validated atomic graph could not be snapshotted safely.",
            )],
        )
    atoms, relationships = validated_rows
    try:
        targets, target_index_issues = _portable_atomic_target_indexes(
            cast(dict[str, Any], source_unit_inventory),
            cast(dict[str, Any], evidence_inventory),
            sources,
        )
        claims, claim_issues = _portable_atomic_claim_index(
            draft, cast(list[dict[str, Any]], sources)
        )
        gaps, gap_issues = _portable_atomic_gap_index(draft)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _portable_atomic_compose(
            target_review, rule_graph, counts,
            [_atomic_issue(
                "ATOMIC_EVIDENCE_INVALID",
                "Atomic evidence indexes could not be built safely.",
            )],
        )
    index_issues: list[dict[str, object]] = []
    index_issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    for incoming, code in (
        (target_index_issues, "ATOMIC_EVIDENCE_INVALID"),
        (claim_issues, "ATOMIC_EVIDENCE_INVALID"),
        (gap_issues, "ATOMIC_GAP_INVALID"),
    ):
        _portable_atomic_extend_issues(
            index_issues, index_issue_keys, incoming, code=code
        )
    if index_issues:
        return _portable_atomic_compose(
            target_review, rule_graph, counts, index_issues
        )
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    invalid_atoms = _portable_atomic_validate_atom_evidence(
        atoms, targets, claims, gaps, issues=issues, issue_keys=issue_keys
    )
    invalid_relationships = _portable_atomic_validate_relationship_evidence(
        relationships, atoms, targets, claims, issues=issues,
        issue_keys=issue_keys,
    )
    brief = draft.get("brief")
    brief_valid = brief is None or isinstance(brief, _PortableBrief)
    bindings = _portable_atomic_brief_bindings(brief if brief_valid else None)
    if not brief_valid:
        _append_atomic_issue(
            issues, issue_keys, "ATOMIC_BRIEF_INVALID",
            "The authored brief is malformed and cannot establish atomic visibility.",
        )
    else:
        _portable_atomic_validate_visibility(
            atoms, relationships, draft, bindings, invalid_atoms,
            invalid_relationships, issues=issues, issue_keys=issue_keys,
        )
    evidence_issue_codes = {
        "ATOMIC_CLAIM_UNKNOWN", "ATOMIC_CLAIM_NOT_SOURCE_SUPPORTED",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET", "ATOMIC_GAP_INVALID",
        "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
    }
    if not any(issue["code"] in evidence_issue_codes for issue in issues):
        projected_reviews = _portable_atomic_project_lead_reviews(
            draft.get("lead_dispositions_v2")
        )
        if projected_reviews is None:
            _append_atomic_issue(
                issues, issue_keys, "ATOMIC_LEAD_RECALL_INVALID",
                "Atomic lead dispositions could not be projected safely.",
            )
        else:
            try:
                recall_draft = dict(draft)
                recall_draft["lead_reviews"] = projected_reviews
                recall = _evaluate_provision_recall(
                    cast(dict[str, Any], evidence_inventory),
                    recall_draft,
                    cast(list[dict[str, Any]], sources),
                )
            except (AttributeError, KeyError, TypeError, ValueError):
                recall = {"valid": False, "unresolved_lead_ids": []}
            if recall.get("valid") is not True:
                unresolved_ids = recall.get("unresolved_lead_ids")
                _append_atomic_issue(
                    issues, issue_keys, "ATOMIC_LEAD_RECALL_INVALID",
                    "Atomic lead dispositions do not satisfy unchanged provision recall.",
                    *(unresolved_ids if isinstance(unresolved_ids, list) else []),
                )
    _portable_atomic_complete_counts(counts, atoms, relationships, bindings)
    return _portable_atomic_compose(target_review, rule_graph, counts, issues)


def _validation_issue(
    level: str, code: str, path: str, message: str, *related_ids: str
) -> dict[str, Any]:
    return {
        "level": level,
        "code": code,
        "path": path,
        "message": message,
        "related_ids": list(related_ids),
    }


def _duplicates(values: list[str], code: str, path: str) -> list[dict[str, Any]]:
    return [
        _validation_issue(
            "error",
            code,
            path,
            f"Identifier {identifier!r} occurs more than once.",
            identifier,
        )
        for identifier, count in Counter(values).items()
        if count > 1
    ]


def _brief_units(
    bundle: dict[str, Any],
) -> list[
    tuple[
        str,
        str,
        tuple[str, ...],
        list[str],
        list[str],
        list[str],
        list[str],
    ]
]:
    brief = bundle.get("brief")
    if brief is None:
        return []
    units: list[
        tuple[
            str,
            str,
            tuple[str, ...],
            list[str],
            list[str],
            list[str],
            list[str],
        ]
    ] = []

    def add_block(path: str, block: dict[str, Any]) -> None:
        if block["kind"] == "paragraph":
            units.append(
                (
                    path,
                    block["purpose"],
                    (block["text"],),
                    block["finding_ids"],
                    block["claim_ids"],
                    block["enforcement_trigger_claim_ids"],
                    block["enforcement_consequence_claim_ids"],
                )
            )
        elif block["kind"] in {"bullet_list", "numbered_list"}:
            units.extend(
                (
                    f"{path}.items[{index}]",
                    block["purpose"],
                    (item["text"],),
                    item["finding_ids"],
                    item["claim_ids"],
                    item["enforcement_trigger_claim_ids"],
                    item["enforcement_consequence_claim_ids"],
                )
                for index, item in enumerate(block["items"])
            )
        else:
            units.extend(
                (
                    f"{path}.rows[{index}]",
                    block["purpose"],
                    tuple(row["cells"]),
                    row["finding_ids"],
                    row["claim_ids"],
                    row["enforcement_trigger_claim_ids"],
                    row["enforcement_consequence_claim_ids"],
                )
                for index, row in enumerate(block["rows"])
            )

    for block_index, block in enumerate(brief["executive_summary"]):
        add_block(f"brief.executive_summary[{block_index}]", block)
    for section_index, section in enumerate(brief["sections"]):
        section_path = f"brief.sections[{section_index}]"
        for block_index, block in enumerate(section["blocks"]):
            add_block(f"{section_path}.blocks[{block_index}]", block)
        for subsection_index, subsection in enumerate(section["subsections"]):
            subsection_path = f"{section_path}.subsections[{subsection_index}]"
            for block_index, block in enumerate(subsection["blocks"]):
                add_block(f"{subsection_path}.blocks[{block_index}]", block)
    return units


def _profiled_brief_issues(
    bundle: dict[str, Any],
    supported_finding_ids: set[str],
    category_by_issue_id: dict[str, str],
    claim_finding_by_id: dict[str, str],
    enforcement_roles_by_claim_id: dict[str, set[str]],
) -> list[dict[str, Any]]:
    brief = bundle.get("brief")
    if brief is None or brief.get("structure_profile") != "regulatory-walk-v1":
        return []

    issues: list[dict[str, Any]] = []
    matter_title = bundle["request"].get("matter_title")
    if not isinstance(matter_title, str) or not matter_title.strip():
        issues.append(
            _validation_issue(
                "error",
                "BRIEF_MATTER_TITLE_MISSING",
                "request.matter_title",
                "A profiled attorney brief requires a concrete matter title.",
                "regulatory-walk-v1",
            )
        )
    sections_by_role: dict[str, list[int]] = {
        role: [] for role, _, _ in CANONICAL_BRIEF_SECTIONS
    }
    canonical_role_by_title = {
        title: role for role, title, _ in CANONICAL_BRIEF_SECTIONS
    }
    for section_index, section in enumerate(brief["sections"]):
        role = section.get("role")
        if role is None:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_SECTION_ROLE_MISSING",
                    f"brief.sections[{section_index}].role",
                    "Every section in a profiled attorney brief must declare a semantic role.",
                    section["section_id"],
                )
            )
            continue
        reserved_role = canonical_role_by_title.get(section["title"])
        if role == "other" and reserved_role is not None:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
                    f"brief.sections[{section_index}].title",
                    "Canonical heading may be used only by its matching section role.",
                    reserved_role,
                )
            )
        if role in sections_by_role:
            sections_by_role[role].append(section_index)

    canonical_index_by_role: dict[str, int] = {}
    for role, title, _ in CANONICAL_BRIEF_SECTIONS:
        matching_indexes = sections_by_role[role]
        if not matching_indexes:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_CANONICAL_SECTION_MISSING",
                    "brief.sections",
                    "Profiled attorney brief is missing a required canonical section.",
                    role,
                )
            )
            continue
        if len(matching_indexes) > 1:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_CANONICAL_SECTION_DUPLICATE",
                    "brief.sections",
                    "Profiled attorney brief contains a canonical section role more than once.",
                    role,
                )
            )
            continue
        section_index = matching_indexes[0]
        canonical_index_by_role[role] = section_index
        if brief["sections"][section_index]["title"] != title:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
                    f"brief.sections[{section_index}].title",
                    "Canonical section role must use its required heading.",
                    role,
                )
            )

    canonical_roles = tuple(role for role, _, _ in CANONICAL_BRIEF_SECTIONS)
    if all(role in canonical_index_by_role for role in canonical_roles):
        canonical_indexes = [canonical_index_by_role[role] for role in canonical_roles]
        if canonical_indexes != sorted(canonical_indexes):
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_CANONICAL_SECTION_ORDER_INVALID",
                    "brief.sections",
                    "Canonical sections must appear in this order: Key Requirements; "
                    "Penalties and Enforcement; Implementation Workplan.",
                    *canonical_roles,
                )
            )

    purpose_contracts = (
        (
            "key_requirements",
            {"legal_analysis", "limitation"},
            "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
            "Key Requirements may contain only legal-analysis or limitation blocks.",
        ),
        (
            "penalties_enforcement",
            {"legal_analysis", "limitation"},
            "BRIEF_PENALTIES_PURPOSE_INVALID",
            "Penalties and Enforcement may contain only legal-analysis or limitation blocks.",
        ),
        (
            "implementation",
            {"application", "client_fact", "limitation"},
            "BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
            (
                "Implementation Workplan may contain only application, client-fact, "
                "or limitation blocks."
            ),
        ),
    )
    for role, allowed, code, message in purpose_contracts:
        if role not in canonical_index_by_role:
            continue
        section_index = canonical_index_by_role[role]
        section = brief["sections"][section_index]
        blocks = [
            (f"brief.sections[{section_index}].blocks[{index}]", block)
            for index, block in enumerate(section["blocks"])
        ]
        for subsection_index, subsection in enumerate(section["subsections"]):
            blocks.extend(
                (
                    f"brief.sections[{section_index}].subsections[{subsection_index}]"
                    f".blocks[{block_index}]",
                    block,
                )
                for block_index, block in enumerate(subsection["blocks"])
            )
        for block_path, block in blocks:
            if block["purpose"] not in allowed:
                issues.append(
                    _validation_issue(
                        "error",
                        code,
                        f"{block_path}.purpose",
                        message,
                        role,
                    )
                )

    finding_by_id = {
        finding["finding_id"]: finding for finding in bundle["findings"]
    }
    for role, _, category in CANONICAL_BRIEF_SECTIONS:
        if category is None or role not in canonical_index_by_role:
            continue
        section_index = canonical_index_by_role[role]
        section_path = f"brief.sections[{section_index}]"
        section_units = [
            unit
            for unit in _brief_units(bundle)
            if unit[0].startswith(f"{section_path}.")
        ]
        section_finding_ids = {
            finding_id
            for _, _, _, finding_ids, claim_ids, _, _ in section_units
            for finding_id in (
                *finding_ids,
                *(
                    claim_finding_by_id[claim_id]
                    for claim_id in claim_ids
                    if claim_id in claim_finding_by_id
                ),
            )
        }
        category_finding_ids = sorted(
            finding_id
            for finding_id in supported_finding_ids
            if finding_id in finding_by_id
            and category_by_issue_id.get(finding_by_id[finding_id]["issue_id"])
            == category
        )
        if category_finding_ids:
            misplaced_ids = sorted(set(category_finding_ids) - section_finding_ids)
            if misplaced_ids:
                code = (
                    "BRIEF_REQUIREMENT_FINDING_MISPLACED"
                    if category == "requirements"
                    else "BRIEF_ENFORCEMENT_FINDING_MISPLACED"
                )
                message = (
                    "Every supported requirements finding must appear in the "
                    "Key Requirements section."
                    if category == "requirements"
                    else "Every supported enforcement finding must appear in the "
                    "Penalties and Enforcement section."
                )
                issues.append(
                    _validation_issue(
                        "error",
                        code,
                        section_path,
                        message,
                        *misplaced_ids,
                    )
                )
            continue

        has_not_established_limitation = any(
            purpose == "limitation"
            and any(text.strip().casefold().startswith("not established:") for text in texts)
            for _, purpose, texts, _, _, _, _ in section_units
        )
        if not has_not_established_limitation:
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_NOT_ESTABLISHED_MISSING",
                    section_path,
                    "A canonical section with no supported category finding must include "
                    "limitation content beginning 'Not established:'.",
                    category,
                )
            )
        if not any(gap["category"] == category for gap in bundle["gaps"]):
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_NOT_ESTABLISHED_GAP_MISSING",
                    "gaps",
                    "A canonical section with no supported category finding requires a "
                    "matching categorized gap.",
                    category,
                )
            )
    penalty_indexes = sections_by_role["penalties_enforcement"]
    if len(penalty_indexes) == 1:
        penalty_path = f"brief.sections[{penalty_indexes[0]}]"
        for path, purpose, _, _, claim_ids, trigger_ids, consequence_ids in _brief_units(
            bundle
        ):
            if not path.startswith(f"{penalty_path}.") or purpose != "legal_analysis":
                continue
            if not trigger_ids or not consequence_ids:
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_ENFORCEMENT_PAIR_MISSING",
                        path,
                        "Supported penalties-and-enforcement analysis must bind both the "
                        "legal trigger and its consequence.",
                    )
                )
                continue
            claim_id_set = set(claim_ids)
            if not set(trigger_ids) <= claim_id_set or not set(
                consequence_ids
            ) <= claim_id_set:
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_ENFORCEMENT_PAIR_INVALID",
                        path,
                        "Enforcement trigger and consequence claims must be included in "
                        "the unit's bound claim identifiers.",
                        *sorted(
                            (set(trigger_ids) | set(consequence_ids)) - claim_id_set
                        ),
                    )
                )
                continue
            invalid_role_ids = sorted(
                {
                    claim_id
                    for claim_id in trigger_ids
                    if "trigger" not in enforcement_roles_by_claim_id.get(claim_id, set())
                }
                | {
                    claim_id
                    for claim_id in consequence_ids
                    if "consequence"
                    not in enforcement_roles_by_claim_id.get(claim_id, set())
                }
            )
            if invalid_role_ids:
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_ENFORCEMENT_ROLE_INVALID",
                        path,
                        "Enforcement trigger and consequence bindings require matching "
                        "typed roles on each source-supported claim.",
                        *invalid_role_ids,
                    )
                )
    return issues


def _validate_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    issues.extend(
        _duplicates(
            [source["source_id"] for source in bundle["sources"]], "SOURCE_ID_DUPLICATE", "sources"
        )
    )
    if bundle.get("brief") is not None:
        if bundle["brief"]["executive_summary"][0]["purpose"] != "legal_analysis":
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL",
                    "brief.executive_summary[0]",
                    "Executive Summary must begin with supported legal analysis about "
                    "the governing authority.",
                )
            )
        issues.extend(
            _duplicates(
                [section["section_id"] for section in bundle["brief"]["sections"]],
                "BRIEF_SECTION_DUPLICATE",
                "brief.sections",
            )
        )
        for section_index, section in enumerate(bundle["brief"]["sections"]):
            issues.extend(
                _duplicates(
                    [item["subsection_id"] for item in section["subsections"]],
                    "BRIEF_SUBSECTION_DUPLICATE",
                    f"brief.sections[{section_index}].subsections",
                )
            )
    issues.extend(
        _duplicates(
            [citation["citation_id"] for citation in bundle["citations"]],
            "CITATION_ID_DUPLICATE",
            "citations",
        )
    )
    issues.extend(
        _duplicates(
            [issue["issue_id"] for issue in bundle["issues"]], "ISSUE_ID_DUPLICATE", "issues"
        )
    )
    issues.extend(
        _duplicates(
            [finding["finding_id"] for finding in bundle["findings"]],
            "FINDING_ID_DUPLICATE",
            "findings",
        )
    )
    issues.extend(
        _duplicates(
            [claim["claim_id"] for finding in bundle["findings"] for claim in finding["claims"]],
            "CLAIM_ID_DUPLICATE",
            "findings[].claims",
        )
    )
    issues.extend(
        _duplicates([gap["gap_id"] for gap in bundle["gaps"]], "GAP_ID_DUPLICATE", "gaps")
    )
    issues.extend(
        _duplicates(
            [item["review_id"] for item in bundle["review_items"]],
            "REVIEW_ID_DUPLICATE",
            "review_items",
        )
    )
    source_by_id = {source["source_id"]: source for source in bundle["sources"]}
    citation_by_id = {citation["citation_id"]: citation for citation in bundle["citations"]}
    issue_ids = {issue["issue_id"] for issue in bundle["issues"]}
    finding_by_id = {finding["finding_id"]: finding for finding in bundle["findings"]}
    claim_by_id = {
        claim["claim_id"]: claim
        for finding in bundle["findings"]
        for claim in finding["claims"]
    }
    claim_finding_by_id = {
        claim["claim_id"]: finding["finding_id"]
        for finding in bundle["findings"]
        for claim in finding["claims"]
    }
    enforcement_roles_by_claim_id = {
        claim["claim_id"]: set(claim.get("enforcement_roles", []))
        for finding in bundle["findings"]
        for claim in finding["claims"]
    }
    supported_finding_ids = {
        finding["finding_id"]
        for finding in bundle["findings"]
        if any(
            claim["kind"] == "source_supported"
            and any(citation_id in citation_by_id for citation_id in claim["citation_ids"])
            for claim in finding["claims"]
        )
    }
    category_by_issue_id = {
        issue["issue_id"]: issue["category"] for issue in bundle["issues"]
    }
    issues.extend(
        _profiled_brief_issues(
            bundle,
            supported_finding_ids,
            category_by_issue_id,
            claim_finding_by_id,
            enforcement_roles_by_claim_id,
        )
    )
    if bundle.get("brief") is not None:
        used_finding_ids: set[str] = set()
        profiled = bundle["brief"].get("structure_profile") == "regulatory-walk-v1"
        for path, purpose, texts, finding_ids, claim_ids, _, _ in _brief_units(bundle):
            if purpose == "legal_analysis" and any(
                SOURCE_FRAMED_LEGAL_LEAD.search(text) for text in texts
            ):
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS",
                        path,
                        "State the supported legal rule directly; reserve source-"
                        "sufficiency framing for limitation content.",
                    )
                )
            known_claim_ids = [
                claim_id for claim_id in claim_ids if claim_id in claim_by_id
            ]
            if profiled and purpose == "legal_analysis":
                if not claim_ids:
                    issues.append(
                        _validation_issue(
                            "error",
                            "BRIEF_LEGAL_ANALYSIS_CLAIM_MISSING",
                            f"{path}.claim_ids",
                            "Profiled legal analysis must bind exact source-supported claims.",
                        )
                    )
                for claim_id in claim_ids:
                    if claim_id in claim_by_id:
                        continue
                    issues.append(
                        _validation_issue(
                            "error",
                            "BRIEF_CLAIM_MISSING",
                            f"{path}.claim_ids",
                            "Attorney brief content references a claim outside the bundle.",
                            claim_id,
                        )
                    )
                bound_claims = [claim_by_id[claim_id] for claim_id in known_claim_ids]

                def has_exact_citations(claim: dict[str, Any]) -> bool:
                    if not claim["citation_ids"]:
                        return False
                    for citation_id in claim["citation_ids"]:
                        citation = citation_by_id.get(citation_id)
                        if citation is None:
                            return False
                        source = source_by_id.get(citation["source_id"])
                        if source is None or (
                            source["normalized_text"][
                                citation["start_char"] : citation["end_char"]
                            ]
                            != citation["quote"]
                        ):
                            return False
                    return True

                invalid_claim_ids = [
                    claim["claim_id"]
                    for claim in bound_claims
                    if claim["kind"] != "source_supported"
                    or not has_exact_citations(claim)
                ]
                if invalid_claim_ids:
                    issues.append(
                        _validation_issue(
                            "error",
                            "BRIEF_CLAIM_EVIDENCE_INVALID",
                            f"{path}.claim_ids",
                            "Bound legal-analysis claims must be source-supported with exact "
                            "resolved citations.",
                            *invalid_claim_ids,
                        )
                    )
                derived_finding_ids = {
                    claim_finding_by_id[claim_id]
                    for claim_id in known_claim_ids
                    if claim_id in claim_finding_by_id
                }
                if finding_ids and set(finding_ids) != derived_finding_ids:
                    issues.append(
                        _validation_issue(
                            "error",
                            "BRIEF_CLAIM_FINDING_MISMATCH",
                            path,
                            "Bound claims must belong exactly to the referenced or derivable "
                            "findings.",
                            *sorted(set(finding_ids) ^ derived_finding_ids),
                        )
                    )
                exact_quotes: list[str] = []
                for claim in bound_claims:
                    for citation_id in claim["citation_ids"]:
                        citation = citation_by_id.get(citation_id)
                        if citation is None:
                            continue
                        source = source_by_id.get(citation["source_id"])
                        if source is None:
                            continue
                        if (
                            source["normalized_text"][
                                citation["start_char"] : citation["end_char"]
                            ]
                            != citation["quote"]
                        ):
                            continue
                        exact_quotes.append(citation["quote"])
                unit_text = " ".join(texts)
                normalized_unit = " ".join(unit_text.split()).casefold()
                normalized_claims = {
                    " ".join(claim["text"].split()).casefold()
                    for claim in bound_claims
                }
                combined_claims = " ".join(
                    " ".join(claim["text"].split()) for claim in bound_claims
                ).casefold()
                lexical_status = _support_status(unit_text, exact_quotes)
                if bound_claims and (
                    normalized_unit not in normalized_claims
                    and normalized_unit != combined_claims
                    and lexical_status != "supported"
                ):
                    issues.append(
                        _validation_issue(
                            "error",
                            "BRIEF_LEGAL_ANALYSIS_TEXT_UNSUPPORTED",
                            path,
                            "Legal-analysis prose must remain lexically anchored to its bound "
                            "claims; this check does not establish semantic entailment.",
                            *known_claim_ids,
                        )
                    )
                used_finding_ids.update(derived_finding_ids)
            missing_ids = [item for item in finding_ids if item not in finding_by_id]
            for finding_id in missing_ids:
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_FINDING_MISSING",
                        f"{path}.finding_ids",
                        "Attorney brief content references a finding outside the bundle.",
                        finding_id,
                    )
                )
            known_ids = [item for item in finding_ids if item in finding_by_id]
            used_finding_ids.update(known_ids)
            unsupported_ids = [
                item for item in known_ids if item not in supported_finding_ids
            ]
            if purpose == "legal_analysis" and not profiled and (
                not known_ids or unsupported_ids
            ):
                issues.append(
                    _validation_issue(
                        "error",
                        "BRIEF_LEGAL_ANALYSIS_UNSUPPORTED",
                        path,
                        "Legal-analysis content must reference findings with resolved evidence.",
                        *unsupported_ids,
                    )
                )
        for finding_id in sorted(supported_finding_ids - used_finding_ids):
            issues.append(
                _validation_issue(
                    "error",
                    "BRIEF_FINDING_OMITTED",
                    "brief",
                    "A source-supported finding is absent from the attorney brief.",
                    finding_id,
                )
            )
    if bundle["request"]["source_mode"] == "web" and not any(
        source["fetch_status"] == "succeeded" and source["source_quality"] == "primary"
        for source in bundle["sources"]
    ):
        issues.append(
            _validation_issue(
                "error",
                "WEB_PRIMARY_AUTHORITY_MISSING",
                "sources",
                "Web research retained no successful primary authority; status and "
                "obligations must not be treated as verified.",
            )
        )
    for gap_index, gap in enumerate(bundle["gaps"]):
        for source_id in gap["source_ids"]:
            if source_id in source_by_id:
                continue
            issues.append(
                _validation_issue(
                    "error",
                    "GAP_SOURCE_MISSING",
                    f"gaps[{gap_index}].source_ids",
                    "Gap references a source that is not in the bundle.",
                    gap["gap_id"],
                    source_id,
                )
            )
    for index, source in enumerate(bundle["sources"]):
        if source["fetch_status"] == "succeeded":
            if source["content_hash"] != _sha256(source["normalized_text"].encode("utf-8")):
                issues.append(
                    _validation_issue(
                        "error",
                        "SOURCE_HASH_MISMATCH",
                        f"sources[{index}].content_hash",
                        "Stored source hash does not match normalized text.",
                        source["source_id"],
                    )
                )
            for field, code, message in (
                (
                    source["canonical_url"],
                    "SOURCE_CANONICAL_URL_MISSING",
                    "Successful source has no canonical public source URL.",
                ),
                (
                    source["publisher"],
                    "SOURCE_PUBLISHER_MISSING",
                    "Successful source has no identified publisher.",
                ),
                (
                    source["jurisdiction"],
                    "SOURCE_JURISDICTION_MISSING",
                    "Successful source has no identified jurisdiction.",
                ),
                (
                    source["authority_type"],
                    "SOURCE_AUTHORITY_TYPE_MISSING",
                    "Successful source has no identified authority type.",
                ),
            ):
                if field is None or not field.strip():
                    issues.append(
                        _validation_issue(
                            "warning",
                            code,
                            f"sources[{index}]",
                            message,
                            source["source_id"],
                        )
                    )
            if source["source_quality"] == "unknown":
                issues.append(
                    _validation_issue(
                        "warning",
                        "SOURCE_QUALITY_UNVERIFIED",
                        f"sources[{index}].source_quality",
                        "Successful source has not been classified as primary or secondary.",
                        source["source_id"],
                    )
                )
        elif not any(source["source_id"] in gap["source_ids"] for gap in bundle["gaps"]):
            issues.append(
                _validation_issue(
                    "error",
                    "FAILED_SOURCE_UNACKNOWLEDGED",
                    f"sources[{index}]",
                    "Failed source retrieval is not represented as an explicit gap.",
                    source["source_id"],
                )
            )
    for index, citation in enumerate(bundle["citations"]):
        source = source_by_id.get(citation["source_id"])
        if source is None:
            issues.append(
                _validation_issue(
                    "error",
                    "CITATION_SOURCE_MISSING",
                    f"citations[{index}].source_id",
                    "Citation references a source that is not in the bundle.",
                    citation["citation_id"],
                    citation["source_id"],
                )
            )
        elif (
            source["normalized_text"][citation["start_char"] : citation["end_char"]]
            != citation["quote"]
        ):
            issues.append(
                _validation_issue(
                    "error",
                    "QUOTE_MISMATCH",
                    f"citations[{index}].quote",
                    "Citation quote does not equal the normalized source slice.",
                    citation["citation_id"],
                    citation["source_id"],
                )
            )
    for finding_index, finding in enumerate(bundle["findings"]):
        if finding["issue_id"] not in issue_ids:
            issues.append(
                _validation_issue(
                    "error",
                    "FINDING_ISSUE_MISSING",
                    f"findings[{finding_index}].issue_id",
                    "Finding references an issue that is not in the bundle.",
                    finding["finding_id"],
                    finding["issue_id"],
                )
            )
        for claim_index, claim in enumerate(finding["claims"]):
            path = f"findings[{finding_index}].claims[{claim_index}]"
            if claim["kind"] == "source_supported" and not claim["citation_ids"]:
                issues.append(
                    _validation_issue(
                        "error",
                        "MATERIAL_CLAIM_UNCITED",
                        f"{path}.citation_ids",
                        "Source-supported claim has no citation.",
                        claim["claim_id"],
                    )
                )
            for citation_id in claim["citation_ids"]:
                if citation_id not in citation_by_id:
                    issues.append(
                        _validation_issue(
                            "error",
                            "CLAIM_CITATION_MISSING",
                            f"{path}.citation_ids",
                            "Claim references a citation that is not in the bundle.",
                            claim["claim_id"],
                            citation_id,
                        )
                    )
            if claim["kind"] == "source_supported" and claim["support_status"] == "unsupported":
                issues.append(
                    _validation_issue(
                        "warning",
                        "CLAIM_SUPPORT_UNSUPPORTED",
                        path,
                        "Lexical support floor failed: low lexical coverage.",
                        claim["claim_id"],
                    )
                )
    supported_categories = {
        category_by_issue_id[finding["issue_id"]]
        for finding in bundle["findings"]
        if finding["issue_id"] in category_by_issue_id
        and any(
            claim["kind"] == "source_supported" and claim["citation_ids"]
            for claim in finding["claims"]
        )
    }
    gap_categories = {gap["category"] for gap in bundle["gaps"]}
    for category in REQUIRED_COVERAGE_CATEGORIES:
        if category in supported_categories or category in gap_categories:
            continue
        issues.append(
            _validation_issue(
                "error",
                "COVERAGE_DIMENSION_MISSING",
                "issues",
                "Required attorney briefing dimension has neither a supported finding "
                "nor a categorized gap.",
                category,
            )
        )
    covered = {finding["jurisdiction"].casefold() for finding in bundle["findings"]}
    covered.update(
        gap["jurisdiction"].casefold() for gap in bundle["gaps"] if gap["jurisdiction"] is not None
    )
    for jurisdiction in bundle["request"]["jurisdictions"]:
        if jurisdiction.casefold() not in covered:
            issues.append(
                _validation_issue(
                    "error",
                    "JURISDICTION_UNCOVERED",
                    "request.jurisdictions",
                    "Requested jurisdiction has neither a finding nor an explicit gap.",
                    jurisdiction,
                )
            )
    issues.sort(
        key=lambda item: (
            item["level"],
            item["code"],
            item["path"],
            item["related_ids"],
        )
    )
    return issues


def _manifest(run_id: str, host_name: str, model_name: str, created_at: str) -> dict[str, Any]:
    updated_at = _now()
    return {
        "run_id": run_id,
        "generator_version": GENERATOR_VERSION,
        "created_at": created_at,
        "updated_at": updated_at,
        "stages": [
            {
                "name": stage,
                "status": "completed",
                "input_fingerprint": _sha256(f"portable\0{run_id}\0{stage}".encode()),
                "started_at": created_at,
                "completed_at": updated_at,
                "error": None,
            }
            for stage in STAGES
        ],
        "provider_metadata": {
            "model_provider": host_name.strip() or "host-agent",
            "model": model_name.strip() or "host-configured-model",
        },
        "configuration_fingerprint": _sha256(b"portable-standard-library-v1"),
    }


def _escape(value: object) -> str:
    text = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=False)
    for control in _MARKDOWN_CONTROLS:
        text = text.replace(control, f"\\{control}")
    return text


def _code(value: object) -> str:
    return html.escape(
        str(value).replace("\r", " ").replace("\n", " "), quote=False
    ).replace("`", "&#96;")


def _display_origin(source: dict[str, Any]) -> str:
    parsed = urlsplit(source["origin"])
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        safe_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            safe_host = f"{safe_host}:{port}"
        return _escape(urlunsplit((parsed.scheme, safe_host, parsed.path, "", "")))
    return _escape(Path(source["origin"]).name or "local source")


def _public_authority_url(source: dict[str, Any]) -> str | None:
    candidate = source.get("canonical_url") or source["origin"]
    if not isinstance(candidate, str):
        return None
    parsed = urlsplit(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    safe_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None:
        safe_host = f"{safe_host}:{port}"
    path = parsed.path.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
    return urlunsplit((parsed.scheme, safe_host, path, "", ""))


def _source_labels(bundle: dict[str, Any]) -> dict[str, str]:
    return {
        source["source_id"]: f"S{index}"
        for index, source in enumerate(bundle["sources"], start=1)
    }


def _supported_finding(finding: dict[str, Any]) -> bool:
    return any(
        claim["kind"] == "source_supported" and claim["citation_ids"]
        for claim in finding["claims"]
    )


def _report_context(bundle: dict[str, Any]) -> dict[str, Any]:
    source_by_id = {source["source_id"]: source for source in bundle["sources"]}
    citation_by_id = {
        citation["citation_id"]: citation for citation in bundle["citations"]
    }
    finding_by_id = {
        finding["finding_id"]: finding for finding in bundle["findings"]
    }
    claim_by_id = {
        claim["claim_id"]: claim
        for finding in bundle["findings"]
        for claim in finding["claims"]
    }
    source_labels = _source_labels(bundle)
    source_order = {
        source["source_id"]: index
        for index, source in enumerate(bundle["sources"])
    }

    def finding_source_ids(finding_ids: list[str]) -> list[str]:
        discovered: set[str] = set()
        for finding_id in finding_ids:
            finding = finding_by_id.get(finding_id)
            if finding is None:
                continue
            for claim in finding["claims"]:
                for citation_id in claim["citation_ids"]:
                    citation = citation_by_id.get(citation_id)
                    if citation is not None and citation["source_id"] in source_by_id:
                        discovered.add(citation["source_id"])
        return sorted(discovered, key=source_order.__getitem__)

    def markers_for_source_ids(source_ids: list[str]) -> str:
        markers: list[str] = []
        for source_id in source_ids:
            label = source_labels[source_id]
            source = source_by_id[source_id]
            public_url = _public_authority_url(source)
            markers.append(f"[{label}]({public_url})" if public_url else f"[{label}]")
        return ", ".join(markers)

    def finding_source_markers(finding_ids: list[str]) -> str:
        return markers_for_source_ids(finding_source_ids(finding_ids))

    def claim_source_markers(claim_ids: list[str]) -> str:
        discovered: set[str] = set()
        for claim_id in claim_ids:
            claim = claim_by_id.get(claim_id)
            if claim is None:
                continue
            for citation_id in claim["citation_ids"]:
                citation = citation_by_id.get(citation_id)
                if citation is not None and citation["source_id"] in source_by_id:
                    discovered.add(citation["source_id"])
        return markers_for_source_ids(
            sorted(discovered, key=source_order.__getitem__)
        )

    return {
        "citation_by_id": citation_by_id,
        "finding_by_id": finding_by_id,
        "finding_source_ids": finding_source_ids,
        "source_by_id": source_by_id,
        "source_labels": source_labels,
        "finding_source_markers": finding_source_markers,
        "claim_source_markers": claim_source_markers,
    }


def _with_markers(
    text: str,
    finding_ids: list[str],
    claim_ids: list[str],
    context: dict[str, Any],
) -> str:
    markers = (
        context["claim_source_markers"](claim_ids)
        if claim_ids
        else context["finding_source_markers"](finding_ids)
    )
    suffix = f" {markers}" if markers else ""
    return f"{_escape(text)}{suffix}"


def _render_block(block: dict[str, Any], context: dict[str, Any]) -> list[str]:
    if block["kind"] == "paragraph":
        return [
            _with_markers(
                block["text"], block["finding_ids"], block["claim_ids"], context
            ),
            "",
        ]
    if block["kind"] in {"bullet_list", "numbered_list"}:
        lines: list[str] = []
        for index, item in enumerate(block["items"], start=1):
            prefix = "-" if block["kind"] == "bullet_list" else f"{index}."
            lines.append(
                f"{prefix} "
                f"{_with_markers(item['text'], item['finding_ids'], item['claim_ids'], context)}"
            )
        lines.append("")
        return lines
    lines = [
        "| " + " | ".join(_escape(column) for column in block["columns"]) + " |",
        "| " + " | ".join("---" for _ in block["columns"]) + " |",
    ]
    for row in block["rows"]:
        cells = [_escape(cell) for cell in row["cells"]]
        markers = (
            context["claim_source_markers"](row["claim_ids"])
            if row["claim_ids"]
            else context["finding_source_markers"](row["finding_ids"])
        )
        if markers:
            cells[-1] = f"{cells[-1]} {markers}"
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _coverage_state(bundle: dict[str, Any], category: str) -> str:
    category_by_issue = {
        issue["issue_id"]: issue["category"] for issue in bundle["issues"]
    }
    has_finding = any(
        category_by_issue.get(finding["issue_id"]) == category
        and _supported_finding(finding)
        for finding in bundle["findings"]
    )
    has_gap = any(gap["category"] == category for gap in bundle["gaps"])
    if has_finding and has_gap:
        return "Partial"
    if has_finding:
        return "Established"
    return "Not established"


def _currentness_state(bundle: dict[str, Any]) -> str:
    authorities = _principal_authorities(bundle)
    category_by_issue = {
        issue["issue_id"]: issue["category"] for issue in bundle["issues"]
    }
    context = _report_context(bundle)
    status_source_ids: set[str] = set()
    for finding in bundle["findings"]:
        if (
            category_by_issue.get(finding["issue_id"]) == "status"
            and _supported_finding(finding)
        ):
            status_source_ids.update(
                context["finding_source_ids"]([finding["finding_id"]])
            )
    status_sources = [
        source
        for source in bundle["sources"]
        if source["source_id"] in status_source_ids
        and source["fetch_status"] == "succeeded"
        and source["source_quality"] == "primary"
    ]
    if status_sources:
        retained_authorities = [
            source.get("citation") or source.get("title") or source["display_name"]
            for source in status_sources
        ]
    elif authorities:
        retained_authorities = authorities
    else:
        retained_authorities = []
    retained_authorities = list(dict.fromkeys(retained_authorities)) or ["not identified"]
    authority_label = (
        "retained cited primary authority"
        if len(retained_authorities) == 1
        else "retained cited primary authorities"
    )
    retained = "; ".join(_escape(authority) for authority in retained_authorities)
    as_of = bundle["request"]["as_of"]
    metadata_dates = sorted(
        {
            match
            for source in status_sources
            if source.get("supersession") is not None
            for match in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", source["supersession"])
            if match <= as_of
        }
    )
    if metadata_dates:
        return (
            "Recorded in retained primary-source metadata through "
            f"{metadata_dates[-1]}; {authority_label}: {retained}; "
            "attorney verification required"
        )
    return (
        f"Not independently verified through {as_of}; {authority_label}: {retained}; "
        "attorney verification required"
    )


def _principal_authorities(bundle: dict[str, Any]) -> list[str]:
    context = _report_context(bundle)
    cited_source_ids: set[str] = set()
    for finding in bundle["findings"]:
        if not _supported_finding(finding):
            continue
        cited_source_ids.update(context["finding_source_ids"]([finding["finding_id"]]))
    authorities: list[str] = []
    for source in bundle["sources"]:
        if (
            source["source_id"] not in cited_source_ids
            or source["fetch_status"] != "succeeded"
            or source["source_quality"] != "primary"
        ):
            continue
        authority = source.get("citation") or source.get("title") or source["display_name"]
        if authority not in authorities:
            authorities.append(authority)
    return authorities


def _metadata_lines(bundle: dict[str, Any]) -> list[str]:
    jurisdictions = ", ".join(
        _escape(item) for item in bundle["request"]["jurisdictions"]
    )
    jurisdiction_label = (
        "Jurisdiction"
        if len(bundle["request"]["jurisdictions"]) == 1
        else "Jurisdictions"
    )
    authorities = _principal_authorities(bundle)
    authority_label = "Principal authorities" if len(authorities) > 1 else "Principal authority"
    source_scope = (
        "Closed universe of supplied materials"
        if bundle["request"]["source_mode"] == "provided-only"
        else "Public-source research"
    )
    effective_dates = sorted(
        {
            source["effective_date"]
            for source in bundle["sources"]
            if source["fetch_status"] == "succeeded"
            and source.get("effective_date") is not None
        }
    )
    lines = [
        f"**{jurisdiction_label}:** {jurisdictions}",
        f"**As of:** {bundle['request']['as_of']}",
        f"**Research scope:** {source_scope}",
        f"**{authority_label}:** "
        + ("; ".join(_escape(item) for item in authorities) if authorities else "Not established"),
        f"**Currentness:** {_currentness_state(bundle)}",
    ]
    if effective_dates:
        date_label = "Operative date" if len(effective_dates) == 1 else "Operative dates"
        lines.append(
            f"**{date_label}:** " + ", ".join(_escape(item) for item in effective_dates)
        )
    return [line for item in lines for line in (item, "")]


def _render_adaptive_sections(
    bundle: dict[str, Any], context: dict[str, Any]
) -> list[str]:
    lines: list[str] = []
    for section in bundle["brief"]["sections"]:
        lines.extend([f"## {_escape(section['title'])}", ""])
        for block in section["blocks"]:
            lines.extend(_render_block(block, context))
        for subsection in section["subsections"]:
            lines.extend([f"### {_escape(subsection['title'])}", ""])
            for block in subsection["blocks"]:
                lines.extend(_render_block(block, context))
    return lines


def _render_fallback_sections(
    bundle: dict[str, Any], context: dict[str, Any]
) -> list[str]:
    findings_by_issue: dict[str, list[dict[str, Any]]] = {}
    for finding in bundle["findings"]:
        if _supported_finding(finding):
            findings_by_issue.setdefault(finding["issue_id"], []).append(finding)
    lines: list[str] = []
    for issue in bundle["issues"]:
        findings = findings_by_issue.get(issue["issue_id"], [])
        if not findings:
            continue
        lines.extend([f"## {_escape(issue['title'])}", ""])
        if issue.get("description"):
            lines.extend([_escape(issue["description"]), ""])
        for finding in findings:
            markers = context["finding_source_markers"]([finding["finding_id"]])
            suffix = f" {markers}" if markers else ""
            lines.extend([f"### {_escape(finding['title'])}{suffix}", ""])
            for claim in finding["claims"]:
                if claim["kind"] == "analysis":
                    lines.extend([_escape(claim["text"]), ""])
            lines.extend(
                [
                    f"**Practical implication:** {_escape(finding['practical_implication'])}",
                    "",
                ]
            )
    return lines


def _render_limitations(gaps: list[dict[str, Any]]) -> list[str]:
    if not gaps:
        return []
    lines = ["## Limitations and Open Questions", ""]
    seen: set[str] = set()
    for gap in gaps:
        if gap["message"] in seen:
            continue
        seen.add(gap["message"])
        lines.append(f"- {_escape(gap['message'])}")
    lines.append("")
    return lines


def _source_section(source: dict[str, Any]) -> str:
    role = source.get("source_role")
    if role is not None:
        return SOURCE_SECTION_TITLES[role]
    if source["source_quality"] == "primary":
        return SOURCE_SECTION_TITLES["official_primary"]
    if source["source_quality"] == "secondary":
        return SOURCE_SECTION_TITLES["secondary"]
    return "Unclassified Sources"


def _concise_source_line(source: dict[str, Any], label: str) -> str:
    parts = [f"- **{label}. {_escape(source['display_name'])}**"]
    if source.get("citation"):
        parts.append(_escape(source["citation"]))
    if source.get("publisher"):
        parts.append(_escape(source["publisher"]))
    public_url = _public_authority_url(source)
    if public_url is not None:
        link_label = (
            "Official source"
            if source.get("source_role") == "official_primary"
            else "Source"
        )
        parts.append(f"[{link_label}]({public_url})")
    else:
        parts.append(f"Source: {_display_origin(source)}")
    if source.get("effective_date"):
        parts.append(f"Effective date: {_escape(source['effective_date'])}")
    if source["fetch_status"] == "failed" and source.get("error") is not None:
        parts.append(f"Retrieval failed: {_escape(source['error']['category'])}")
    return ". ".join(parts) + "."


def _render_sources(bundle: dict[str, Any]) -> list[str]:
    labels = _source_labels(bundle)
    lines = ["## Sources Consulted", ""]
    for heading in SOURCE_SECTION_ORDER:
        sources = [
            source for source in bundle["sources"] if _source_section(source) == heading
        ]
        if not sources:
            continue
        lines.extend([f"### {heading}", ""])
        lines.extend(
            _concise_source_line(source, labels[source["source_id"]])
            for source in sources
        )
        lines.append("")
    return lines


def _render_report(bundle: dict[str, Any]) -> str:
    context = _report_context(bundle)
    title = bundle["request"].get("matter_title") or "Attorney research briefing"
    lines = [
        f"# {_escape(title)}",
        "",
        *_metadata_lines(bundle),
        "## Executive Summary",
        "",
    ]
    if bundle.get("brief") is not None:
        for block in bundle["brief"]["executive_summary"]:
            lines.extend(_render_block(block, context))
        lines.extend(_render_adaptive_sections(bundle, context))
    else:
        supported = [
            finding for finding in bundle["findings"] if _supported_finding(finding)
        ]
        if supported:
            for finding in supported:
                lines.append(
                    "- "
                    + _with_markers(
                        finding["title"], [finding["finding_id"]], [], context
                    )
                )
            lines.append("")
        else:
            lines.extend(
                [
                    "The retained materials did not support a substantive legal conclusion.",
                    "",
                ]
            )
        lines.extend(_render_fallback_sections(bundle, context))
    lines.extend(_render_limitations(bundle["gaps"]))
    lines.extend(_render_sources(bundle))
    lines.extend([f"*{_escape(bundle['disclaimer'])}*", ""])
    return "\n".join(lines)


def _quote_block(text: str) -> list[str]:
    safe_lines = [_escape(line) for line in text.splitlines()] or [""]
    return [f"> {line}" for line in safe_lines]


def _audit_source(source: dict[str, Any], label: str) -> list[str]:
    lines = [
        f"### {label}. {_escape(source['display_name'])}",
        "",
        f"- Retained origin: {_display_origin(source)}",
        f"- Retrieval: {source['fetch_status']}",
        f"- Quality: {source['source_quality']}",
    ]
    public_url = _public_authority_url(source)
    if public_url is not None:
        lines.append(f"- Canonical source: <{public_url}>")
    for detail_label, key in (
        ("Publisher", "publisher"),
        ("Jurisdiction", "jurisdiction"),
        ("Authority type", "authority_type"),
        ("Citation", "citation"),
        ("Effective date", "effective_date"),
        ("Supersession", "supersession"),
        ("Language", "language"),
    ):
        value = source.get(key)
        if value is not None:
            lines.append(f"- {detail_label}: {_escape(value)}")
    if source["fetch_status"] == "failed" and source.get("error") is not None:
        lines.append(f"- Failure category: {_escape(source['error']['category'])}")
    lines.append("")
    return lines


def _render_audit(bundle: dict[str, Any]) -> str:
    title = bundle["request"].get("matter_title") or "Attorney research briefing"
    source_by_id = {source["source_id"]: source for source in bundle["sources"]}
    source_labels = _source_labels(bundle)
    evidence_labels = {
        citation["citation_id"]: f"E{index}"
        for index, citation in enumerate(bundle["citations"], start=1)
    }
    validation = bundle.get("validation")
    validation_status = (
        "not run"
        if validation is None
        else "valid"
        if validation["valid"]
        else "invalid"
    )
    lines = [
        f"# {_escape(title)}: Evidence and Validation Audit",
        "",
        "## Research Scope",
        "",
        f"**Research question:** {_escape(bundle['request']['question'])}",
        "",
        "**Jurisdictions:** "
        + ", ".join(_escape(item) for item in bundle["request"]["jurisdictions"]),
        "",
        f"**As of:** {bundle['request']['as_of']}",
        "",
        f"**Source mode:** {_escape(bundle['request']['source_mode'])}",
        "",
        f"**Deterministic validation:** {validation_status}",
        "",
        "## Retained Sources",
        "",
    ]
    for source in bundle["sources"]:
        lines.extend(_audit_source(source, source_labels[source["source_id"]]))
    lines.extend(["## Exact Evidence", ""])
    if not bundle["citations"]:
        lines.extend(["No exact evidence excerpt was resolved.", ""])
    for citation in bundle["citations"]:
        evidence_label = evidence_labels[citation["citation_id"]]
        source = source_by_id.get(citation["source_id"])
        source_label = source_labels.get(citation["source_id"], citation["source_id"])
        source_name = source["display_name"] if source is not None else citation["source_id"]
        citation_text = (
            f", {_escape(source['citation'])}"
            if source is not None and source.get("citation") is not None
            else ""
        )
        lines.extend(
            [
                f"### {evidence_label}. {_escape(source_name)}{citation_text} "
                f"({_escape(source_label)})",
                "",
            ]
        )
        lines.extend(_quote_block(citation["quote"]))
        lines.append("")
    lines.extend(["## Validation and Review", "", "### Research Gap Audit", ""])
    if not bundle["gaps"]:
        lines.extend(["No research gap code was recorded.", ""])
    for gap in bundle["gaps"]:
        lines.append(f"- `{_code(gap['code'])}`: {_escape(gap['message'])}")
    lines.extend(["", "### Deterministic Validation", ""])
    if validation is None:
        lines.extend(["The bundle has not been validated.", ""])
    elif not validation["issues"]:
        lines.extend(["No deterministic validation issues were found.", ""])
    else:
        for issue in validation["issues"]:
            lines.append(
                f"- {issue['level']}: `{_code(issue['code'])}` at "
                f"`{_code(issue['path'])}`: {_escape(issue['message'])}"
            )
        lines.append("")
    lines.extend(["### Attorney Review Required", ""])
    if not bundle["review_items"]:
        lines.extend(
            [
                "No additional review item was generated, but attorney review remains mandatory.",
                "",
            ]
        )
    for item in bundle["review_items"]:
        lines.append(f"- `{_code(item['code'])}`: {_escape(item['message'])}")
    lines.extend(["", bundle["disclaimer"], "", "### Methodology and Run Metadata", ""])
    lines.extend(
        [
            "COMBINE stages: Collect, Organize, Map, Build, Inspect, Note, Export.",
            "",
            f"- Run ID: `{_code(bundle['manifest']['run_id'])}`",
            f"- Generator: `{_code(bundle['generator_version'])}`",
            f"- Updated: {_escape(bundle['manifest']['updated_at'])}",
        ]
    )
    provider_metadata = bundle["manifest"]["provider_metadata"]
    for key in ("model_provider", "model"):
        value = provider_metadata.get(key)
        if value is not None:
            lines.append(f"- {_escape(key.replace('_', ' ').title())}: {_escape(value)}")
    lines.append("")
    return "\n".join(lines)


def _readiness_replay_generation_validation_v1(
    *,
    draft: dict[str, Any],
    dossier: dict[str, Any],
    bundle: dict[str, Any],
    coverage: dict[str, Any],
    draft_bytes: bytes,
    dossier_bytes: bytes,
    coverage_bytes: bytes,
    report_bytes: bytes,
    receipt: dict[str, Any],
) -> None:
    """Replay the portable generation proof consumed by delivery readiness.

    This deliberately shares the retained generation algorithms instead of
    introducing a second set of coverage or validation thresholds.
    """
    if set(dossier) != {
        "coverage_contract_version",
        "evidence_inventory",
        "gaps",
        "request",
        "schema_version",
        "source_mode",
        "source_unit_inventory",
        "sources",
    } or dossier.get("schema_version") != "1.0":
        raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")
    raw_sources = dossier.get("sources")
    raw_gaps = dossier.get("gaps")
    request = dossier.get("request")
    if (
        not isinstance(raw_sources, list)
        or not isinstance(raw_gaps, list)
        or not isinstance(request, dict)
    ):
        raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")
    if set(request) != {
        "as_of",
        "context",
        "excluded_topics",
        "jurisdictions",
        "matter_title",
        "output_instructions",
        "question",
        "request_id",
        "source_inputs",
        "source_mode",
    }:
        raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
    for key in ("request_id", "question"):
        if (
            not isinstance(request[key], str)
            or request[key] != request[key].strip()
            or not request[key]
        ):
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
    for key in ("matter_title", "context", "output_instructions"):
        value = request[key]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
    try:
        if date.fromisoformat(request["as_of"]).isoformat() != request["as_of"]:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.") from error
    jurisdictions = request["jurisdictions"]
    excluded_topics = request["excluded_topics"]
    source_inputs = request["source_inputs"]
    if (
        request["source_mode"] not in {"provided-only", "web"}
        or not isinstance(jurisdictions, list)
        or not jurisdictions
        or any(not isinstance(item, str) or not item.strip() for item in jurisdictions)
        or len(jurisdictions) != len(set(jurisdictions))
        or not isinstance(excluded_topics, list)
        or any(not isinstance(item, str) for item in excluded_topics)
        or not isinstance(source_inputs, list)
        or not source_inputs
    ):
        raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
    source_input_fields = {
        "authority_type",
        "canonical_url",
        "citation",
        "effective_date",
        "jurisdiction",
        "language",
        "license_assertion",
        "location",
        "publisher",
        "source_quality",
        "source_role",
        "supersession",
        "title",
    }
    for raw_input in source_inputs:
        if not isinstance(raw_input, dict) or set(raw_input) != source_input_fields:
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
        if (
            not isinstance(raw_input["location"], str)
            or not raw_input["location"].strip()
            or raw_input["source_quality"] not in SOURCE_QUALITIES
            or raw_input["source_role"] not in SOURCE_ROLES | {None}
            or not isinstance(raw_input["license_assertion"], str)
        ):
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
        try:
            canonical_url = _canonical_public_url(
                raw_input["canonical_url"], "request canonical URL"
            )
            if canonical_url != raw_input["canonical_url"]:
                raise ValueError
        except (PortableInputError, ValueError) as error:
            raise PortableInputError(
                "INVALID_REQUEST", "The validation request is invalid."
            ) from error
        if raw_input["language"] is not None and (
            not isinstance(raw_input["language"], str) or not raw_input["language"].strip()
        ):
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
    for raw_gap in raw_gaps:
        if not isinstance(raw_gap, dict) or set(raw_gap) != {
            "category",
            "code",
            "gap_id",
            "jurisdiction",
            "message",
            "presentation_role",
            "source_ids",
        }:
            raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")
        if (
            any(
                not isinstance(raw_gap[key], str) or not raw_gap[key].strip()
                for key in ("gap_id", "code", "message")
            )
            or raw_gap["category"] not in ISSUE_CATEGORIES
            or raw_gap["presentation_role"] not in PRESENTATION_ROLES | {None}
            or (
                raw_gap["jurisdiction"] is not None
                and not isinstance(raw_gap["jurisdiction"], str)
            )
            or not isinstance(raw_gap["source_ids"], list)
            or any(not isinstance(item, str) for item in raw_gap["source_ids"])
        ):
            raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")
    sources: list[dict[str, Any]] = []
    for raw_source in raw_sources:
        source = _portable_source_record(raw_source)
        if source is None:
            raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")
        sources.append(source)
    evidence_inventory = _build_evidence_inventory(sources)
    source_unit_inventory = _build_source_unit_inventory(sources)
    contract_version = dossier.get("coverage_contract_version")
    expected_dossier = {
        "schema_version": "1.0",
        "coverage_contract_version": contract_version,
        "source_mode": request.get("source_mode"),
        "request": request,
        "sources": sources,
        "gaps": raw_gaps,
        "evidence_inventory": evidence_inventory,
        "source_unit_inventory": source_unit_inventory,
    }
    if (
        contract_version not in {COVERAGE_CONTRACT_VERSION, ATOMIC_COVERAGE_CONTRACT_VERSION}
        or dossier.get("source_mode") != request.get("source_mode")
        or dossier != expected_dossier
        or dossier_bytes != _canonical_bytes(expected_dossier) + b"\n"
    ):
        raise PortableInputError("INVALID_DOSSIER", "The validation dossier is invalid.")

    parsed_draft = _finalization_draft(draft)
    if parsed_draft != draft or draft_bytes != _canonical_bytes(parsed_draft) + b"\n":
        raise PortableInputError("INVALID_DRAFT", "The validation draft is invalid.")
    if contract_version == ATOMIC_COVERAGE_CONTRACT_VERSION:
        expected_coverage = _evaluate_portable_atomic_coverage(
            source_unit_inventory,
            evidence_inventory,
            parsed_draft,
            sources,
        )
        coverage_issue_count = len(expected_coverage.get("issues", []))
    else:
        coverage_draft = parsed_draft
        if parsed_draft.get("coverage_contract_version") != COVERAGE_CONTRACT_VERSION:
            coverage_draft = dict(parsed_draft)
            coverage_draft["coverage_contract_version"] = None
        expected_coverage = _evaluate_coverage_closure(
            evidence_inventory,
            source_unit_inventory,
            coverage_draft,
            sources,
        )
        coverage_issue_count = len(expected_coverage["lead_recall"]["issues"]) + len(
            expected_coverage["proposition_coverage"]["issues"]
        )
    if (
        coverage != expected_coverage
        or coverage_bytes != _canonical_bytes(expected_coverage) + b"\n"
        or expected_coverage.get("valid") is not True
        or receipt.get("coverage_review_hash") != expected_coverage.get("coverage_review_hash")
        or receipt.get("coverage_issue_count") != coverage_issue_count
    ):
        raise PortableInputError("INVALID_COVERAGE", "The validation coverage proof is invalid.")

    findings, citations, review_items = _build_analysis(parsed_draft, sources)
    gaps = [
        _gap(
            item["code"],
            item["message"],
            item["jurisdiction"],
            item["source_ids"],
            category=item["category"],
            presentation_role=item["presentation_role"],
        )
        for item in parsed_draft["gaps"]
    ]
    gap_keys = {(gap["code"], gap["jurisdiction"], tuple(gap["source_ids"])) for gap in gaps}
    for source in sources:
        key = ("SOURCE_RETRIEVAL_FAILED", source["jurisdiction"], (source["source_id"],))
        if source["fetch_status"] == "failed" and key not in gap_keys:
            gaps.append(
                _gap(
                    "SOURCE_RETRIEVAL_FAILED",
                    "A requested source could not be retrieved or normalized.",
                    source["jurisdiction"],
                    [source["source_id"]],
                )
            )
            gap_keys.add(key)
    category_by_issue_id = {
        issue["issue_id"]: issue["category"] for issue in parsed_draft["issues"]
    }
    supported_categories = {
        category_by_issue_id[finding["issue_id"]]
        for finding in findings
        if finding["issue_id"] in category_by_issue_id
        and any(
            claim["kind"] == "source_supported" and claim["citation_ids"]
            for claim in finding["claims"]
        )
    }
    gap_categories = {gap["category"] for gap in gaps}
    for category in REQUIRED_COVERAGE_CATEGORIES:
        if category not in supported_categories and category not in gap_categories:
            gaps.append(
                _gap(
                    f"COVERAGE_{category.upper()}_NOT_ESTABLISHED",
                    _COVERAGE_GAP_MESSAGES[category],
                    None,
                    [],
                    category=category,
                )
            )
    covered = {finding["jurisdiction"].casefold() for finding in findings}
    covered.update(
        gap["jurisdiction"].casefold()
        for gap in gaps
        if gap["jurisdiction"] is not None
    )
    for jurisdiction in request.get("jurisdictions", []):
        if not isinstance(jurisdiction, str):
            raise PortableInputError("INVALID_REQUEST", "The validation request is invalid.")
        if jurisdiction.casefold() not in covered:
            gaps.append(
                _gap(
                    "JURISDICTION_UNCOVERED",
                    "No supported finding was produced for this jurisdiction.",
                    jurisdiction,
                    [],
                )
            )
    replay_fields = {
        "request": request,
        "sources": sources,
        "issues": parsed_draft["issues"],
        "findings": findings,
        "citations": citations,
        "gaps": gaps,
        "review_items": review_items,
        "brief": parsed_draft["brief"],
    }
    if any(bundle.get(key) != value for key, value in replay_fields.items()):
        raise PortableInputError("INVALID_BUNDLE", "The validation bundle cannot be replayed.")
    manifest = bundle.get("manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "run_id",
        "generator_version",
        "created_at",
        "updated_at",
        "stages",
        "provider_metadata",
        "configuration_fingerprint",
    }:
        raise PortableInputError("INVALID_BUNDLE", "The validation manifest is invalid.")
    if (
        bundle.get("schema_version") != "1.1"
        or bundle.get("generator_version") != manifest.get("generator_version")
        or bundle.get("disclaimer") != DISCLAIMER
        or bundle.get("requires_attorney_review") is not True
        or not isinstance(manifest.get("run_id"), str)
        or not manifest["run_id"].strip()
        or not isinstance(manifest.get("generator_version"), str)
        or not manifest["generator_version"].strip()
    ):
        raise PortableInputError("INVALID_BUNDLE", "The validation manifest is invalid.")
    for key in ("created_at", "updated_at"):
        value = manifest[key]
        try:
            if not isinstance(value, str) or datetime.fromisoformat(value) is None:
                raise ValueError
        except ValueError as error:
            raise PortableInputError(
                "INVALID_BUNDLE", "The validation manifest is invalid."
            ) from error
    provider_metadata = manifest["provider_metadata"]
    if (
        not isinstance(provider_metadata, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in provider_metadata.items()
        )
    ):
        raise PortableInputError("INVALID_BUNDLE", "The validation manifest is invalid.")
    stages = manifest["stages"]
    if not isinstance(stages, list) or len(stages) != len(STAGES):
        raise PortableInputError("INVALID_BUNDLE", "The validation stages are invalid.")
    for name, stage in zip(STAGES, stages, strict=True):
        if not isinstance(stage, dict) or set(stage) != {
            "name",
            "status",
            "input_fingerprint",
            "started_at",
            "completed_at",
            "error",
        }:
            raise PortableInputError("INVALID_BUNDLE", "The validation stages are invalid.")
        if (
            stage["name"] != name
            or stage["status"] not in {"pending", "running", "completed", "failed", "skipped"}
            or stage["error"] is not None
        ):
            raise PortableInputError("INVALID_BUNDLE", "The validation stages are invalid.")
        fingerprint = stage["input_fingerprint"]
        if fingerprint is not None and (
            not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            raise PortableInputError("INVALID_BUNDLE", "The validation stages are invalid.")
        for key in ("started_at", "completed_at"):
            value = stage[key]
            try:
                if value is not None and (
                    not isinstance(value, str) or datetime.fromisoformat(value) is None
                ):
                    raise ValueError
            except ValueError as error:
                raise PortableInputError(
                    "INVALID_BUNDLE", "The validation stages are invalid."
                ) from error
    validation_base = dict(bundle)
    validation_base["validation"] = None
    validation_base["bundle_hash"] = None
    validation_issues = _validate_bundle(validation_base)
    validation = bundle.get("validation")
    blocking_count = sum(
        item["code"] in BLOCKING_REVIEW_CODES for item in review_items
    )
    if (
        not isinstance(validation, dict)
        or set(validation) != {"valid", "issues", "validated_at"}
        or validation.get("valid") is not True
        or validation.get("issues") != validation_issues
        or not isinstance(validation.get("validated_at"), str)
        or any(item.get("level") == "error" for item in validation_issues)
        or receipt.get("validation_issue_count") != len(validation_issues)
        or receipt.get("blocking_review_count") != blocking_count
        or _render_report(bundle).encode("utf-8") != report_bytes
    ):
        raise PortableInputError("INVALID_BUNDLE", "The validation bundle proof is invalid.")


def finalize(
    matter: Path,
    draft_path: Path,
    *,
    host_name: str,
    model_name: str,
) -> tuple[dict[str, object], int]:
    _validate_layout(matter)
    request_path = matter / "request.json"
    dossier_path = matter / "agent-dossier.json"
    if not request_path.is_file() or not dossier_path.is_file():
        raise PortableInputError(
            "MATTER_NOT_PREPARED", "Run the prepare command before finalizing analysis."
    )
    request = _require_object(_read_json(request_path, "INVALID_REQUEST"), "request")
    dossier = _require_object(_read_json(dossier_path, "INVALID_DOSSIER"), "dossier")
    raw_sources = dossier.get("sources")
    raw_inventory = dossier.get("evidence_inventory", {"leads": []})
    if not isinstance(raw_sources, list) or not isinstance(raw_inventory, dict):
        raise PortableInputError(
            "INVALID_DOSSIER", "The prepared source inventory is invalid."
        )
    prepared_sources: list[dict[str, Any]] = []
    for raw_source in raw_sources:
        prepared_source = _portable_source_record(raw_source)
        if prepared_source is None:
            raise PortableInputError(
                "INVALID_DOSSIER", "The prepared source inventory is invalid."
            )
        prepared_sources.append(prepared_source)
    contract_version = dossier.get("coverage_contract_version")
    has_contract = "coverage_contract_version" in dossier
    has_units = "source_unit_inventory" in dossier
    if contract_version in (
        COVERAGE_CONTRACT_VERSION,
        ATOMIC_COVERAGE_CONTRACT_VERSION,
    ):
        raw_units = dossier.get("source_unit_inventory")
        if not isinstance(raw_units, dict):
            raise PortableInputError(
                "INVALID_DOSSIER", "The prepared source-unit inventory is invalid."
            )
    elif not has_contract and not has_units:
        raw_units = None
    else:
        raise PortableInputError(
            "INVALID_DOSSIER", "The prepared coverage contract is invalid."
        )
    try:
        draft = _finalization_draft(
            _read_json(draft_path.expanduser().resolve(strict=True), "INVALID_DRAFT")
        )
    except PortableInputError as error:
        if error.code == "INVALID_INPUT":
            raise PortableInputError("INVALID_DRAFT", str(error)) from None
        raise
    if not draft["findings"]:
        raise PortableInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must contain at least one substantive finding.",
        )
    if not any(
        claim["kind"] == "source_supported" and claim["proposed_citations"]
        for finding in draft["findings"]
        for claim in finding["claims"]
    ):
        raise PortableInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must contain at least one source-supported claim with evidence.",
        )
    if draft["brief"] is None:
        raise PortableInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must include an authored attorney brief.",
        )
    stored_draft = matter / "analysis-draft.json"
    _write_json(stored_draft, draft)
    if contract_version == ATOMIC_COVERAGE_CONTRACT_VERSION:
        assert isinstance(raw_units, dict)
        coverage_review = _evaluate_portable_atomic_coverage(
            raw_units,
            raw_inventory,
            draft,
            prepared_sources,
        )
        proposition_coverage_valid = coverage_review["valid"] is True
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issues = coverage_review.get("issues")
        coverage_issue_count = (
            len(coverage_issues) if isinstance(coverage_issues, list) else 0
        )
    elif contract_version == COVERAGE_CONTRACT_VERSION:
        assert isinstance(raw_units, dict)
        coverage_draft = draft
        if draft.get("coverage_contract_version") != COVERAGE_CONTRACT_VERSION:
            coverage_draft = dict(draft)
            coverage_draft["coverage_contract_version"] = None
        coverage_review = _evaluate_coverage_closure(
            raw_inventory,
            raw_units,
            coverage_draft,
            prepared_sources,
        )
        proposition_coverage_valid: bool | None = (
            coverage_review["proposition_coverage"]["valid"] is True
        )
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issue_count = len(coverage_review["lead_recall"]["issues"]) + len(
            coverage_review["proposition_coverage"]["issues"]
        )
    else:
        coverage_review = _evaluate_provision_recall(
            raw_inventory, draft, prepared_sources
        )
        proposition_coverage_valid = None
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issue_count = len(coverage_review["issues"])
    coverage_path = matter / "coverage-review.json"
    _write_json(coverage_path, coverage_review)
    findings, citations, review_items = _build_analysis(draft, prepared_sources)
    gaps = [
        _gap(
            item["code"],
            item["message"],
            item["jurisdiction"],
            item["source_ids"],
            category=item["category"],
            presentation_role=item["presentation_role"],
        )
        for item in draft["gaps"]
    ]
    gap_keys = {(gap["code"], gap["jurisdiction"], tuple(gap["source_ids"])) for gap in gaps}
    for source in prepared_sources:
        key = ("SOURCE_RETRIEVAL_FAILED", source["jurisdiction"], (source["source_id"],))
        if source["fetch_status"] == "failed" and key not in gap_keys:
            gaps.append(
                _gap(
                    "SOURCE_RETRIEVAL_FAILED",
                    "A requested source could not be retrieved or normalized.",
                    source["jurisdiction"],
                    [source["source_id"]],
                )
            )
            gap_keys.add(key)
    category_by_issue_id = {
        issue["issue_id"]: issue["category"] for issue in draft["issues"]
    }
    supported_categories = {
        category_by_issue_id[finding["issue_id"]]
        for finding in findings
        if finding["issue_id"] in category_by_issue_id
        and any(
            claim["kind"] == "source_supported" and claim["citation_ids"]
            for claim in finding["claims"]
        )
    }
    gap_categories = {gap["category"] for gap in gaps}
    for category in REQUIRED_COVERAGE_CATEGORIES:
        if category in supported_categories or category in gap_categories:
            continue
        code = f"COVERAGE_{category.upper()}_NOT_ESTABLISHED"
        gaps.append(
            _gap(
                code,
                _COVERAGE_GAP_MESSAGES[category],
                None,
                [],
                category=category,
            )
        )
    covered = {finding["jurisdiction"].casefold() for finding in findings}
    covered.update(
        gap["jurisdiction"].casefold() for gap in gaps if gap["jurisdiction"] is not None
    )
    for jurisdiction in request["jurisdictions"]:
        if jurisdiction.casefold() not in covered:
            gaps.append(
                _gap(
                    "JURISDICTION_UNCOVERED",
                    "No supported finding was produced for this jurisdiction.",
                    jurisdiction,
                    [],
                )
            )
    created_at = prepared_sources[0]["retrieved_at"] if prepared_sources else _now()
    bundle: dict[str, Any] = {
        "schema_version": "1.1",
        "generator_version": GENERATOR_VERSION,
        "request": request,
        "manifest": _manifest(request["request_id"], host_name, model_name, created_at),
        "sources": prepared_sources,
        "issues": draft["issues"],
        "findings": findings,
        "citations": citations,
        "gaps": gaps,
        "review_items": review_items,
        "brief": draft["brief"],
        "validation": None,
        "disclaimer": DISCLAIMER,
        "requires_attorney_review": True,
        "bundle_hash": None,
    }
    validation_issues = _validate_bundle(bundle)
    valid = not any(issue["level"] == "error" for issue in validation_issues)
    bundle["validation"] = {
        "valid": valid,
        "issues": validation_issues,
        "validated_at": _now(),
    }
    hash_payload = dict(bundle)
    hash_payload.pop("bundle_hash", None)
    bundle["bundle_hash"] = _sha256(_canonical_bytes(hash_payload))
    run_dir = matter / "runs" / request["request_id"]
    bundle_path = run_dir / "bundle.json"
    report_path = run_dir / "report.md"
    audit_path = run_dir / "audit.md"
    _write_json(bundle_path, bundle)
    _atomic_write(report_path, _render_report(bundle).encode("utf-8"))
    _atomic_write(audit_path, _render_audit(bundle).encode("utf-8"))
    blocking_count = sum(item["code"] in BLOCKING_REVIEW_CODES for item in review_items)
    evidence_precision_valid = valid and blocking_count == 0
    completed = evidence_precision_valid and provision_recall_valid
    receipt: dict[str, object] = {
        "analysis_draft": str(stored_draft),
        "audit": str(audit_path),
        "blocking_review_count": blocking_count,
        "bundle": str(bundle_path),
        "coverage_issue_count": coverage_issue_count,
        "coverage_review": str(coverage_path),
        "coverage_review_hash": coverage_review["coverage_review_hash"],
        "evidence_precision_valid": evidence_precision_valid,
        "proposition_coverage_valid": proposition_coverage_valid,
        "provision_recall_valid": provision_recall_valid,
        "report": str(report_path),
        "status": "completed" if completed else "review-required",
        "valid": valid,
        "validation_issue_count": len(validation_issues),
    }
    _write_json(matter / "validation-receipt.json", receipt)
    return receipt, 0 if completed else 4


def _add_payload_response_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider-name", default=argparse.SUPPRESS)
    parser.add_argument("--model-name", default=argparse.SUPPRESS)
    parser.add_argument(
        "--judge-isolation",
        choices=("fresh_context", "scripted_fixture"),
        default=argparse.SUPPRESS,
    )


def _parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(prog="harvest-skill")
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=JsonArgumentParser
    )
    baseline_init_parser = subparsers.add_parser("eval-baseline-init")
    baseline_init_parser.add_argument("--input", required=True)
    baseline_init_parser.add_argument("--run", required=True)
    baseline_init_parser.add_argument("--nonce-hex", required=True)
    baseline_init_parser.add_argument("--prior-baseline", action="append")
    baseline_init_parser.add_argument("--correction")
    baseline_next_parser = subparsers.add_parser("eval-baseline-next")
    baseline_next_parser.add_argument("--run", required=True)
    baseline_submit_parser = subparsers.add_parser("eval-baseline-submit-safe")
    baseline_submit_parser.add_argument("--run", required=True)
    baseline_submit_parser.add_argument("--response", required=True)
    baseline_submit_parser.add_argument("--provider-name", required=True)
    baseline_submit_parser.add_argument("--model-name", required=True)
    baseline_submit_parser.add_argument(
        "--judge-isolation",
        choices=("fresh_context", "scripted_fixture"),
        required=True,
    )
    baseline_status_parser = subparsers.add_parser("eval-baseline-status")
    baseline_status_parser.add_argument("--run", required=True)
    baseline_verify_parser = subparsers.add_parser("eval-baseline-verify")
    baseline_verify_parser.add_argument("--run", required=True)
    readiness_init_parser = subparsers.add_parser("eval-readiness-init")
    readiness_init_parser.add_argument("--baseline-run", required=True)
    readiness_init_parser.add_argument("--qualification-run", required=True)
    readiness_init_parser.add_argument("--generation-run", required=True)
    readiness_init_parser.add_argument("--validation-receipt", required=True)
    readiness_init_parser.add_argument("--run", required=True)
    readiness_init_parser.add_argument("--historical-v22-run")
    readiness_init_parser.add_argument(
        "--historical-report-label", choices=("A", "B")
    )
    readiness_next_parser = subparsers.add_parser("eval-readiness-next")
    readiness_next_parser.add_argument("--run", required=True)
    readiness_submit_parser = subparsers.add_parser("eval-readiness-submit-safe")
    readiness_submit_parser.add_argument("--run", required=True)
    readiness_submit_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(readiness_submit_parser)
    readiness_status_parser = subparsers.add_parser("eval-readiness-status")
    readiness_status_parser.add_argument("--run", required=True)
    readiness_verify_parser = subparsers.add_parser("eval-readiness-verify")
    readiness_verify_parser.add_argument("--run", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--charter", required=True)
    prepare_parser.add_argument("--matter", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--matter", required=True)
    finalize_parser.add_argument("--draft", required=True)
    finalize_parser.add_argument("--host", default="host-agent")
    finalize_parser.add_argument("--model", default="host-configured-model")
    eval_init_parser = subparsers.add_parser("eval-init")
    eval_init_parser.add_argument(
        "--protocol", choices=("2.1", "2.2"), default="2.1"
    )
    eval_init_parser.add_argument("--case", required=True)
    eval_init_parser.add_argument("--run", required=True)
    eval_init_parser.add_argument("--seed-hex", required=True)
    eval_next_parser = subparsers.add_parser("eval-next")
    eval_next_parser.add_argument("--run", required=True)
    eval_preflight_parser = subparsers.add_parser("eval-preflight")
    eval_preflight_parser.add_argument("--run", required=True)
    eval_preflight_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(eval_preflight_parser)
    eval_submit_parser = subparsers.add_parser("eval-submit")
    eval_submit_parser.add_argument("--run", required=True)
    eval_submit_parser.add_argument("--response", required=True)
    eval_submit_safe_parser = subparsers.add_parser("eval-submit-safe")
    eval_submit_safe_parser.add_argument("--run", required=True)
    eval_submit_safe_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(eval_submit_safe_parser)
    eval_status_parser = subparsers.add_parser("eval-status")
    eval_status_parser.add_argument("--run", required=True)
    eval_verify_parser = subparsers.add_parser("eval-verify")
    eval_verify_parser.add_argument("--run", required=True)
    eval_stop_parser = subparsers.add_parser("eval-stop-inconclusive")
    eval_stop_parser.add_argument("--run", required=True)
    eval_stop_parser.add_argument("--reason", required=True)
    eval_resume_parser = subparsers.add_parser("eval-resume")
    eval_resume_parser.add_argument("--run", required=True)
    eval_resume_parser.add_argument("--scripted-responses", required=True)
    eval_qualify_init_parser = subparsers.add_parser("eval-qualify-init")
    eval_qualify_init_parser.add_argument("--case", required=True)
    eval_qualify_init_parser.add_argument("--run", required=True)
    eval_qualify_init_parser.add_argument("--nonce-hex", required=True)
    eval_qualify_next_parser = subparsers.add_parser("eval-qualify-next")
    eval_qualify_next_parser.add_argument("--run", required=True)
    eval_qualify_submit_parser = subparsers.add_parser("eval-qualify-submit")
    eval_qualify_submit_parser.add_argument("--run", required=True)
    eval_qualify_submit_parser.add_argument("--response", required=True)
    eval_qualify_status_parser = subparsers.add_parser("eval-qualify-status")
    eval_qualify_status_parser.add_argument("--run", required=True)
    eval_qualify_verify_parser = subparsers.add_parser("eval-qualify-verify")
    eval_qualify_verify_parser.add_argument("--run", required=True)
    eval_gen_init_parser = subparsers.add_parser("eval-gen-init")
    eval_gen_init_parser.add_argument("--input", required=True)
    eval_gen_init_parser.add_argument("--run", required=True)
    eval_gen_init_parser.add_argument("--nonce-hex", required=True)
    eval_gen_next_parser = subparsers.add_parser("eval-gen-next")
    eval_gen_next_parser.add_argument("--run", required=True)
    eval_gen_submit_parser = subparsers.add_parser("eval-gen-submit")
    eval_gen_submit_parser.add_argument("--run", required=True)
    eval_gen_submit_parser.add_argument("--response", required=True)
    eval_gen_status_parser = subparsers.add_parser("eval-gen-status")
    eval_gen_status_parser.add_argument("--run", required=True)
    eval_gen_verify_parser = subparsers.add_parser("eval-gen-verify")
    eval_gen_verify_parser.add_argument("--run", required=True)
    return parser


class _EvaluationIntegrityError(ValueError):
    """Translate the reviewed substrate's integrity failure to the CLI contract."""


class _GenerationIntegrityError(ValueError):
    """Translate generation-capsule integrity failure to the CLI contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _evaluation_substrate() -> Any:
    path = Path(__file__).with_name("attorney_eval_portable.py")
    spec = importlib.util.spec_from_file_location("attorney_eval_portable", path)
    if spec is None or spec.loader is None:
        raise _EvaluationIntegrityError("evaluation substrate is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _generation_substrate() -> Any:
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "regulatory_harvest"
        / "evaluation"
        / "attorney_generation.py"
    )
    spec = importlib.util.spec_from_file_location("attorney_generation_portable", path)
    if spec is None or spec.loader is None:
        raise _GenerationIntegrityError("GENERATION_INTEGRITY_INVALID")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _portable_fixture_relative(path: Path, root: Path, *, name: str) -> str:
    try:
        value = Path(os.path.abspath(path))
        relative = value.relative_to(root)
    except (OSError, ValueError) as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", f"{name} must be below the fixture root."
        ) from error
    if not relative.parts:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", f"{name} must be a regular local fixture."
        )
    return relative.as_posix()


def _portable_evaluation_case(
    path: Path,
    *,
    substrate: Any | None = None,
    generation_substrate: Any | None = None,
) -> tuple[dict[str, object], dict[str, Path]]:
    """Load the small local fixture grammar without importing project models."""
    sub = _evaluation_substrate() if substrate is None else substrate
    gen = _generation_substrate() if generation_substrate is None else generation_substrate
    root = Path(os.path.abspath(path.parent))
    case_relative = _portable_fixture_relative(path, root, name="case fixture")

    def safe_fixture_path(relative: object, *, name: str) -> str:
        if (
            type(relative) is not str
            or not relative
            or Path(relative).is_absolute()
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise PortableInputError(
                "EVALUATION_CASE_INVALID", f"{name} has an unsafe fixture path"
            )
        return relative

    def fixture_bytes(storage: Any, relative: object, *, name: str) -> bytes:
        relative = safe_fixture_path(relative, name=name)
        try:
            return cast(bytes, storage.read_artifact(relative))
        except sub.EvaluationIntegrityError as error:
            raise PortableInputError(
                "EVALUATION_CASE_INVALID", f"{name} is unavailable"
            ) from error

    def exact_text(storage: Any, relative: object, *, name: str) -> str:
        try:
            text = fixture_bytes(storage, relative, name=name).decode("utf-8")
        except UnicodeDecodeError as error:
            raise PortableInputError(
                "EVALUATION_CASE_INVALID", f"{name} is not UTF-8."
            ) from error
        if not text.replace("\ufeff", "").strip():
            raise PortableInputError("EVALUATION_CASE_INVALID", f"{name} is blank.")
        return text

    try:
        with sub._open_run_storage(root) as storage:
            raw = fixture_bytes(storage, case_relative, name="case fixture")
            value = json.loads(raw.decode("utf-8"))
            canonical = sub.canonical_json_bytes(value)
            if raw not in {canonical, canonical + b"\n"}:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID", "The case fixture is not canonical JSON."
                )
            if type(value) is not dict or set(value) != {
                "case_id",
                "mode",
                "question",
                "jurisdiction",
                "as_of",
                "requested_authorities",
                "sources",
                "candidates",
                "client_facts_path",
                "schema_version",
            }:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID", "case fixture has an unexpected shape"
                )
            if value["schema_version"] != "1.1":
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID",
                    "case fixture schema version is unsupported for initialization",
                )
            if type(value["question"]) is not str:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID", "The case question must be a string."
                )
            case_question = value["question"]
            sources_raw = value["sources"]
            candidates_raw = value["candidates"]
            if type(sources_raw) is not list or type(candidates_raw) is not list:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID", "The case fixture arrays are invalid."
                )
            sources: list[dict[str, object]] = []
            for item in sources_raw:
                if type(item) is not dict or set(item) != {
                    "source_id",
                    "title",
                    "path",
                    "jurisdiction",
                    "authority_type",
                    "source_role",
                    "source_quality",
                    "completeness",
                    "language",
                }:
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID", "A case source has an unexpected shape."
                    )
                if any(
                    type(item[field]) is not str
                    for field in (
                        "source_id",
                        "title",
                        "path",
                        "jurisdiction",
                        "authority_type",
                        "source_role",
                        "source_quality",
                        "completeness",
                        "language",
                    )
                ):
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID",
                        "A case source contains a non-string value.",
                    )
                text = exact_text(storage, item["path"], name="source fixture")
                sources.append(
                    {
                        "source_id": item["source_id"],
                        "title": item["title"],
                        "normalized_text": text,
                        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "jurisdiction": item["jurisdiction"],
                        "authority_type": item["authority_type"],
                        "source_role": item["source_role"],
                        "source_quality": item["source_quality"],
                        "completeness": item["completeness"],
                        "language": item["language"],
                    }
                )
            client_facts = (
                None
                if value["client_facts_path"] is None
                else exact_text(
                    storage,
                    value["client_facts_path"],
                    name="client facts fixture",
                )
            )
            expected_source_hashes = {
                cast(str, item["source_id"]): cast(str, item["content_hash"])
                for item in sources
            }
            expected_client_facts_hash = (
                None
                if client_facts is None
                else hashlib.sha256(client_facts.encode("utf-8")).hexdigest()
            )
            candidates: list[dict[str, object]] = []
            generation_capsule_paths: dict[str, Path] = {}
            for item in candidates_raw:
                if type(item) is not dict or set(item) != {
                    "candidate_id",
                    "external_report_path",
                    "generation_capsule_path",
                    "role",
                }:
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID", "case candidate has an unexpected shape"
                    )
                candidate_id = item["candidate_id"]
                if type(candidate_id) is not str:
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID", "candidate_id must be a string."
                    )
                capsule_path = item["generation_capsule_path"]
                external_path = item["external_report_path"]
                if (capsule_path is None) == (external_path is None):
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID",
                        "case candidate must identify exactly one report source",
                    )
                if capsule_path is not None:
                    capsule_relative = safe_fixture_path(
                        capsule_path, name="generation capsule"
                    )
                    try:
                        provenance, report_bytes, request = (
                            gen.load_completed_generation_capsule_context(
                                root / capsule_relative
                            )
                        )
                    except gen.GenerationInputError as error:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "generation capsule is incomplete",
                        ) from error
                    except gen.GenerationIntegrityError as error:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID", str(error)
                        ) from error
                    try:
                        text = report_bytes.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "The generation capsule report is not UTF-8.",
                        ) from error
                    if not text.replace("\ufeff", "").strip():
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "The generation capsule report is blank.",
                        )
                    record = cast(dict[str, object], provenance["generation_record"])
                    if record["candidate_id"] != candidate_id:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "generation capsule candidate_id does not match the case",
                        )
                    if record["source_hashes"] != expected_source_hashes:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "Generation capsule sources do not match the common case evidence."
                        )
                    if record["client_facts_hash"] != expected_client_facts_hash:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "Generation capsule client facts do not match the common case evidence."
                        )
                    if request["question"] != case_question:
                        raise PortableInputError(
                            "EVALUATION_CASE_INVALID",
                            "Generation capsule question does not match the evaluation question."
                        )
                    generation_capsule_paths[candidate_id] = root / capsule_relative
                else:
                    text = exact_text(
                        storage, external_path, name="external report fixture"
                    )
                    provenance = {"kind": "external"}
                candidates.append(
                    {
                        "candidate_id": candidate_id,
                        "role": item["role"],
                        "report_text": text,
                        "report_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "validation_receipt": provenance,
                    }
                )
            storage.assert_root_identity()
    except PortableInputError:
        raise
    except sub.EvaluationIntegrityError as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", "The case fixture is unavailable."
        ) from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", "The case fixture is invalid."
        ) from error
    return (
        {
            "schema_version": "1.1",
            "case_id": value["case_id"],
            "mode": value["mode"],
            "question": case_question,
            "jurisdiction": value["jurisdiction"],
            "as_of": value["as_of"],
            "requested_authorities": value["requested_authorities"],
            "sources": sources,
            "candidates": candidates,
            "client_facts": client_facts,
        },
        generation_capsule_paths,
    )


def _portable_qualification_case(
    path: Path,
    *,
    substrate: Any | None = None,
) -> dict[str, object]:
    """Load the strict source-only fixture without package model imports."""
    sub = _evaluation_substrate() if substrate is None else substrate
    root = Path(os.path.abspath(path.parent))
    case_relative = _portable_fixture_relative(
        path,
        root,
        name="qualification case fixture",
    )

    def safe_relative(relative: object, *, name: str) -> str:
        if (
            type(relative) is not str
            or not relative
            or Path(relative).is_absolute()
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise PortableInputError(
                "EVALUATION_CASE_INVALID", f"{name} has an unsafe fixture path."
            )
        return relative

    def artifact_bytes(storage: Any, relative: object, *, name: str) -> bytes:
        try:
            return cast(bytes, storage.read_artifact(safe_relative(relative, name=name)))
        except sub.EvaluationIntegrityError as error:
            raise PortableInputError(
                "EVALUATION_CASE_INVALID", f"{name} is unavailable."
            ) from error

    try:
        with sub._open_run_storage(root) as storage:
            raw = artifact_bytes(storage, case_relative, name="qualification case fixture")
            value = json.loads(raw.decode("utf-8"))
            if type(value) is not dict or raw not in {
                sub.canonical_json_bytes(value),
                sub.canonical_json_bytes(value) + b"\n",
            }:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID",
                    "The qualification case fixture is not canonical JSON.",
                )
            required = {
                "case_id",
                "mode",
                "question",
                "jurisdiction",
                "as_of",
                "requested_authorities",
                "sources",
                "schema_version",
            }
            schema_version = value.get("schema_version")
            if schema_version == "1.1":
                required.update({"build_binding", "language_treatments"})
            elif schema_version != "1.0":
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID",
                    "The qualification case fixture has an unexpected shape.",
                )
            if set(value) != required:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID",
                    "The qualification case fixture has an unexpected shape.",
                )
            sources_raw = value["sources"]
            if type(sources_raw) is not list:
                raise PortableInputError(
                    "EVALUATION_CASE_INVALID",
                    "The qualification case sources must be an array.",
                )
            required_source_fields = {
                "source_id",
                "title",
                "path",
                "jurisdiction",
                "authority_type",
                "source_role",
                "source_quality",
                "completeness",
                "language",
            }
            optional_source_fields = {
                "qualification_role",
                "canonical_url",
                "publisher",
                "version",
                "effective_date",
                "supersession",
                "relationship_ids",
            }
            sources: list[dict[str, object]] = []
            for item in sources_raw:
                if (
                    type(item) is not dict
                    or not required_source_fields.issubset(item)
                    or set(item) - required_source_fields - optional_source_fields
                ):
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID",
                        "A qualification case source has an unexpected shape.",
                    )
                qualification_role = item.get("qualification_role")
                if qualification_role not in {None, "operative_text", "status_currentness"}:
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID",
                        "A qualification case source has an invalid qualification role.",
                    )
                try:
                    text = artifact_bytes(
                        storage,
                        item["path"],
                        name="source fixture",
                    ).decode("utf-8")
                except UnicodeDecodeError as error:
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID", "A source fixture is not UTF-8."
                    ) from error
                if not text.replace("\ufeff", "").strip():
                    raise PortableInputError(
                        "EVALUATION_CASE_INVALID", "A source fixture is blank."
                    )
                relationship_ids = item.get("relationship_ids", [])
                sources.append(
                    {
                        "source_id": item["source_id"],
                        "title": item["title"],
                        "normalized_text": text,
                        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "canonical_url": item.get("canonical_url"),
                        "publisher": item.get("publisher"),
                        "jurisdiction": item["jurisdiction"],
                        "authority_type": item["authority_type"],
                        "source_role": item["source_role"],
                        "source_quality": item["source_quality"],
                        "completeness": item["completeness"],
                        "language": item["language"],
                        "version": item.get("version"),
                        "effective_date": item.get("effective_date"),
                        "supersession": item.get("supersession"),
                        "relationship_ids": relationship_ids,
                    }
                )
            qualification = {
                "schema_version": schema_version,
                "case_id": value["case_id"],
                "mode": value["mode"],
                "question": value["question"],
                "jurisdiction": value["jurisdiction"],
                "as_of": value["as_of"],
                "requested_authorities": value["requested_authorities"],
                "sources": sources,
            }
            if schema_version == "1.1":
                qualification.update(
                    {
                        "build_binding": value["build_binding"],
                        "language_treatments": value["language_treatments"],
                    }
                )
            result = cast(dict[str, object], sub.validate_qualification_case(qualification))
            storage.assert_root_identity()
            return result
    except PortableInputError:
        raise
    except sub.PortableEvaluationInputError as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", "The qualification case fixture is invalid."
        ) from error
    except sub.EvaluationIntegrityError as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", "The qualification case fixture is unavailable."
        ) from error
    except (OSError, RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PortableInputError(
            "EVALUATION_CASE_INVALID", "The qualification case fixture is invalid."
        ) from error


def _physical_eval_run_path(value: str) -> Path:
    """Normalize a run physically through only a trusted root-level alias."""
    try:
        expanded = Path(value).expanduser()
        if expanded.anchor == os.sep and len(expanded.parts) > 1:
            root_component = Path(expanded.anchor) / expanded.parts[1]
            if root_component.is_symlink():
                physical_root = Path(os.path.realpath(root_component))
                expanded = physical_root.joinpath(*expanded.parts[2:])
        return Path(os.path.abspath(expanded))
    except (OSError, RuntimeError, ValueError) as error:
        raise PortableInputError(
            "EVALUATION_INPUT_INVALID", "The run path cannot be normalized safely."
        ) from error


def _eval_json(sub: Any, value: object) -> None:
    print(sub.canonical_json_bytes(value).decode("utf-8"))


def _eval_exit(sub: Any, state: dict[str, object], run: Path) -> int:
    terminal = state["terminal_status"]
    if terminal is None:
        return EVAL_EXIT_SUCCESS
    protocol = sub._v2_protocol(run)
    if protocol == "2.2":
        if terminal == "INCONCLUSIVE":
            return EVAL_EXIT_INCONCLUSIVE
        manifest, files = sub._v22_verified(run)
        if manifest["terminal_status"] != "COMPLETED":
            raise sub.EvaluationIntegrityError("EVALUATOR_V22_TERMINAL_STATUS")
        result = cast(
            dict[str, object],
            sub.parse_canonical_json_bytes(files["result.json"], location="result.json"),
        )
        v22_reports = cast(list[dict[str, object]], result["reports"])
        return (
            EVAL_EXIT_FAIL
            if any(
                cast(dict[str, object], report["sensitivity"])["absolute_disposition"]
                == "FAIL"
                for report in v22_reports
            )
            else EVAL_EXIT_SUCCESS
        )
    if protocol == "2.1":
        if terminal in {"INCONCLUSIVE", "INCONCLUSIVE_MECHANICAL"}:
            return EVAL_EXIT_INCONCLUSIVE
        manifest, files = sub._v21_verified(run)
        if manifest["terminal_status"] != "COMPLETED":
            raise sub.EvaluationIntegrityError("EVALUATOR_V21_TERMINAL_STATUS")
        try:
            result = sub.parse_canonical_json_bytes(files["result.json"], location="result.json")
        except KeyError as error:
            raise sub.EvaluationIntegrityError("EVALUATOR_V21_RESULT_REQUIRED") from error
        if type(result) is not dict or type(result.get("reports")) is not list:
            raise sub.EvaluationIntegrityError("EVALUATOR_V21_RESULT")
        v21_reports = cast(list[dict[str, object]], result["reports"])
        dispositions = [
            cast(dict[str, object], report.get("reconciliation", {})).get(
                "absolute_disposition"
            )
            for report in v21_reports
        ]
        if not dispositions or any(
            disposition not in {"PASS", "FAIL", "INCONCLUSIVE"}
            for disposition in dispositions
        ):
            raise sub.EvaluationIntegrityError("EVALUATOR_V21_RESULT")
        return EVAL_EXIT_FAIL if "FAIL" in dispositions else EVAL_EXIT_SUCCESS
    if terminal == "case-invalid":
        return EVAL_EXIT_INCONCLUSIVE
    if terminal == "inconclusive":
        return EVAL_EXIT_INCONCLUSIVE
    if protocol == "2.0":
        manifest, files = sub._v2_verified(run)
        if manifest["terminal_status"] != "completed":
            raise sub.EvaluationIntegrityError("EVALUATOR_V2_TERMINAL_STATUS")
        try:
            result = sub.parse_canonical_json_bytes(files["result.json"], location="result.json")
        except KeyError as error:
            raise sub.EvaluationIntegrityError("EVALUATOR_V2_RESULT_REQUIRED") from error
        if type(result) is not dict:
            raise sub.EvaluationIntegrityError("EVALUATOR_V2_RESULT")
        result_fingerprint = result.get("result_fingerprint")
        result_without_fingerprint = dict(result)
        result_without_fingerprint.pop("result_fingerprint", None)
        calculated_fingerprint = sub._sha256(sub.canonical_json_bytes(result_without_fingerprint))
        if (
            type(result_fingerprint) is not str
            or result_fingerprint != calculated_fingerprint
            or manifest["result_hash"] != result_fingerprint
        ):
            raise sub.EvaluationIntegrityError("EVALUATOR_V2_RESULT_FINGERPRINT")
        reports = result.get("reports")
        if (
            type(reports) is not list
            or not reports
            or any(
                type(report) is not dict
                or report.get("absolute_disposition") not in {"PASS", "FAIL", "INCONCLUSIVE"}
                for report in reports
            )
        ):
            raise sub.EvaluationIntegrityError("EVALUATOR_V2_RESULT")
        return (
            EVAL_EXIT_FAIL
            if any(report["absolute_disposition"] == "FAIL" for report in reports)
            else EVAL_EXIT_SUCCESS
        )
    _, result = sub.load_verified_evaluation_run(run)
    reports = cast(list[dict[str, object]], result["reports"])
    return (
        EVAL_EXIT_FAIL
        if any(report["absolute_disposition"] == "FAIL" for report in reports)
        else EVAL_EXIT_SUCCESS
    )


def _portable_eval_response(sub: Any, path: Path) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PortableInputError(
            "EVALUATION_RESPONSE_INVALID", "The response is unavailable."
        ) from error
    if len(data) > _EVAL_RESPONSE_MAX_BYTES:
        raise PortableInputError(
            "EVALUATION_RESPONSE_INVALID", "The response exceeds the size limit."
        )
    try:
        value = json.loads(data.decode("utf-8"))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PortableInputError(
            "EVALUATION_RESPONSE_INVALID", "The response must use exact canonical JSON."
        ) from error
    _assert_eval_json_depth(value)
    try:
        canonical = sub.canonical_json_bytes(value)
    except sub.EvaluationIntegrityError as error:
        raise PortableInputError(
            "EVALUATION_RESPONSE_INVALID", "The response must use exact canonical JSON."
        ) from error
    if data != canonical:
        raise PortableInputError(
            "EVALUATION_RESPONSE_INVALID", "The response must use exact canonical JSON."
        )
    if not isinstance(value, dict):
        raise PortableInputError("EVALUATION_RESPONSE_INVALID", "The response must be an object.")
    return value


def _portable_guarded_eval_response(
    sub: Any,
    path: Path,
) -> dict[str, object] | None:
    """Return one canonical object or a bounded sentinel for guarded submission."""
    try:
        return _portable_eval_response(sub, path)
    except (OSError, PortableInputError, RecursionError, UnicodeError, TypeError, ValueError):
        return None


def _portable_guarded_v2_response(
    sub: Any,
    args: argparse.Namespace,
    run: Path,
) -> dict[str, object] | None:
    """Read a full response or deterministically wrap one role-authored payload."""
    value = _portable_guarded_eval_response(sub, Path(args.response))
    if value is None:
        return None
    metadata = (
        getattr(args, "provider_name", None),
        getattr(args, "model_name", None),
        getattr(args, "judge_isolation", None),
    )
    if not any(item is not None for item in metadata):
        return value
    if any(item is None for item in metadata):
        return None
    request = sub.next_judge_request(run)
    if not isinstance(request, dict):
        return None
    provider_name, model_name, judge_isolation = metadata
    return {
        "schema_version": sub._v2_protocol(run),
        "operation": request["operation"],
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": provider_name,
        "model_name": model_name,
        "judge_isolation": judge_isolation,
        "payload": value,
    }


def _assert_eval_json_depth(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _EVAL_RESPONSE_MAX_DEPTH:
            raise PortableInputError(
                "EVALUATION_RESPONSE_INVALID", "The response exceeds the nesting-depth limit."
            )
        if isinstance(current, dict):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)


def _v22_scripted_fixture(sub: Any, path: Path) -> list[dict[str, object]]:
    try:
        fixture = Path(os.path.abspath(path))
        root = Path(os.path.abspath(path.parent))
        relative = fixture.relative_to(root)
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("unsafe scripted draft fixture")
        with sub._open_run_storage(root) as storage:
            data = storage.read_artifact(
                relative.as_posix(), max_bytes=sub._V22_MAX_JSON_BYTES
            )
            storage.assert_root_identity()
    except (OSError, ValueError, sub.EvaluationIntegrityError) as error:
        raise PortableInputError(
            "EVALUATION_INPUT_INVALID",
            "scripted draft fixture is unavailable",
        ) from error
    try:
        value = sub.parse_canonical_json_bytes(data, location="scripted draft fixture")
    except sub.EvaluationIntegrityError as error:
        raise PortableInputError(
            "EVALUATION_INPUT_INVALID",
            "scripted draft fixture is not canonical JSON",
        ) from error
    if (
        type(value) is not dict
        or set(value) != {"fixture_type", "responses"}
        or value.get("fixture_type") != "local-scripted-drafts-v2.2"
    ):
        raise PortableInputError(
            "EVALUATION_INPUT_INVALID",
            "scripted drafts are not a Protocol 2.2 local fixture",
        )
    responses = value.get("responses")
    if type(responses) is not list:
        raise PortableInputError("EVALUATION_INPUT_INVALID", "scripted drafts must be an array")
    result: list[dict[str, object]] = []
    seen: set[bytes] = set()
    codes = {
        "DRAFT_INVALID", "DRAFT_TOO_LARGE", "EVIDENCE_NOT_FOUND",
        "EVIDENCE_AMBIGUOUS", "REFERENCE_UNKNOWN", "SUBSTANCE_MISSING",
        "ITEM_LIMIT_EXCEEDED", "CONFLICTING_ITEMS",
    }
    for raw in responses:
        if type(raw) is not dict or set(raw) != {"draft", "expect", "operation"}:
            raise PortableInputError(
                "EVALUATION_INPUT_INVALID",
                "scripted draft has an unexpected shape",
            )
        expectation = raw.get("expect")
        if type(raw.get("operation")) is not str or type(expectation) is not dict:
            raise PortableInputError("EVALUATION_INPUT_INVALID", "scripted draft is malformed")
        if set(expectation) != {
            "attempt",
            "clarification_codes",
            "request_fingerprint",
        }:
            raise PortableInputError(
                "EVALUATION_INPUT_INVALID",
                "scripted draft expectation has an unexpected shape",
            )
        clarification = expectation.get("clarification_codes")
        if (
            type(expectation.get("attempt")) is not int
            or expectation["attempt"] not in {1, 2}
            or type(expectation.get("request_fingerprint")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", cast(str, expectation["request_fingerprint"])) is None
            or type(clarification) is not list
            or any(type(code) is not str for code in clarification)
        ):
            raise PortableInputError(
                "EVALUATION_INPUT_INVALID",
                "scripted draft expectation is malformed",
            )
        if raw["operation"] not in sub._V22_OPERATIONS or any(
            code not in codes for code in clarification
        ):
            raise PortableInputError(
                "EVALUATION_INPUT_INVALID",
                "scripted draft expectation is unsupported",
            )
        signature = sub.canonical_json_bytes(raw)
        if signature in seen:
            raise PortableInputError("EVALUATION_INPUT_INVALID", "scripted draft is duplicated")
        seen.add(signature)
        result.append(cast(dict[str, object], raw))
    return result


def _v22_drive_script(
    sub: Any, run: Path, scripted: list[dict[str, object]]
) -> tuple[bool, int]:
    entries = list(scripted)
    while (request := sub.next_evaluator_request_v22(run)) is not None:
        clarification: tuple[str, ...] = ()
        accepted = False
        for attempt in (1, 2):
            if not entries:
                raise PortableInputError("EVALUATION_INPUT_INVALID", "scripted drafts exhausted")
            entry = entries.pop(0)
            expectation = cast(dict[str, object], entry["expect"])
            if (
                entry["operation"] != request["operation"]
                or expectation["request_fingerprint"] != request["request_fingerprint"]
                or expectation["attempt"] != attempt
                or expectation["clarification_codes"] != list(clarification)
            ):
                raise PortableInputError(
                    "EVALUATION_INPUT_INVALID",
                    "scripted draft prompt mismatched",
                )
            response, clarification = sub._v22_compile_draft(
                request,
                entry["draft"],
                {
                    "provider_name": "local-scripted-fixture",
                    "model_name": "no-provider",
                    "judge_isolation": "scripted_fixture",
                },
            )
            if response is not None:
                sub.submit_evaluator_response_v22(run, response)
                accepted = True
                break
        if not accepted:
            if entries:
                raise PortableInputError(
                    "EVALUATION_INPUT_INVALID", "scripted drafts contain unused entries"
                )
            return True, EVAL_EXIT_ENGINE_PAUSED
    if entries:
        raise PortableInputError(
            "EVALUATION_INPUT_INVALID", "scripted drafts contain unused entries"
        )
    state = sub.resume_evaluation_v22(run)
    return False, _eval_exit(sub, state, run)


def _v22_nonterminal_payload(sub: Any, run: Path) -> dict[str, object]:
    manifest, _ = sub._v22_verified(run)
    pending = [call for call in manifest["calls"] if call["state"] == "pending"]
    if len(pending) != 1 or manifest["terminal_status"] is not None:
        raise sub.EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    call = pending[0]
    public = call["call_id"]
    if call["operation"] in {"source_review_fragment", "source_audit_fragment"}:
        public = f"{str(call['operation']).replace('_', '-')}-{int(call['fragment_ordinal']):04d}"
    return {
        "compiler_contract_fingerprint": manifest["compiler_contract_fingerprint"],
        "manifest_root": manifest["manifest_fingerprint"],
        "pending_call": public, "phase": manifest["phase"],
    }


def _v22_result_payload(
    sub: Any, run: Path, *, judge_mode: str
) -> dict[str, object]:
    manifest, files = sub._v22_verified(run)
    result = cast(
        dict[str, object],
        sub.parse_canonical_json_bytes(
            files["result.json"], location="result.json"
        ),
    )
    reports = [
        {
            "absolute_disposition": cast(
                dict[str, object], item["sensitivity"]
            )["absolute_disposition"],
            "reason_codes": cast(dict[str, object], item["sensitivity"])["reason_codes"],
        }
        for item in cast(list[dict[str, object]], result["reports"])
    ]
    return {
        "all_issue_codes": sorted(
            {
                code
                for report in reports
                for code in cast(list[str], report["reason_codes"])
            }
        ),
        "comparative_disposition": None
        if result["comparison"] is None
        else cast(dict[str, object], result["comparison"])["disposition"],
        "judge_mode": judge_mode, "manifest_root": manifest["manifest_fingerprint"],
        "reports": reports, "terminal_state": result["terminal_status"],
    }


def _run_v22_eval_command(sub: Any, args: argparse.Namespace, run: Path) -> int:
    if args.command == "eval-next":
        request = sub.next_evaluator_request_v22(run)
        if request is None:
            state = sub.resume_evaluation_v22(run)
            _eval_json(sub, None)
            return _eval_exit(sub, state, run)
        _eval_json(sub, request)
        return EVAL_EXIT_SUCCESS
    if args.command == "eval-preflight":
        try:
            response = _portable_eval_response(sub, Path(args.response))
            result = sub.preflight_evaluator_response_v22(run, response)
        except PortableInputError:
            result = {"valid": False, "diagnostics": ["EXTERNAL_RESPONSE_INVALID"]}
        _eval_json(sub, result)
        return EVAL_EXIT_SUCCESS if result["valid"] else EVAL_EXIT_INPUT
    if args.command == "eval-submit":
        response = _portable_eval_response(sub, Path(args.response))
        try:
            state = sub.submit_evaluator_response_v22(run, response)
        except (sub.PortableEvaluationInputError, TypeError, ValueError) as error:
            raise PortableInputError(
                "EXTERNAL_RESPONSE_INVALID",
                "The strict response does not bind the pending request.",
            ) from error
        _eval_json(sub, state)
        return _eval_exit(sub, state, run)
    if args.command == "eval-submit-safe":
        try:
            response = _portable_eval_response(sub, Path(args.response))
            guarded = sub.guarded_submit_evaluator_response_v22(run, response)
        except PortableInputError:
            guarded = {
                "accepted": False,
                "preflight": {
                    "valid": False,
                    "diagnostics": ["EXTERNAL_RESPONSE_INVALID"],
                },
            }
        except (TypeError, ValueError) as error:
            raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
        _eval_json(sub, guarded)
        return EVAL_EXIT_SUCCESS if guarded["accepted"] else EVAL_EXIT_INPUT
    if args.command == "eval-stop-inconclusive":
        raise PortableInputError(
            "EVALUATION_MUTATION_UNSUPPORTED",
            "Protocol 2.2 has no mechanical terminalization command.",
        )
    if args.command == "eval-resume":
        scripted = _v22_scripted_fixture(sub, Path(args.scripted_responses))
        sub._v22_verified(run)
        try:
            with tempfile.TemporaryDirectory(prefix="regulatory-harvest-v22-probe-") as temporary:
                probe = Path(os.path.realpath(temporary)) / "run"
                shutil.copytree(run, probe, symlinks=True)
                _v22_drive_script(sub, probe, scripted)
        except PortableInputError:
            raise
        except OSError as error:
            raise PortableInputError(
                "EVALUATION_INPUT_INVALID", "scripted draft probe could not be constructed"
            ) from error
        paused, exit_code = _v22_drive_script(sub, run, scripted)
        if paused:
            _eval_json(
                sub,
                {
                    "error": "evaluation_engine_paused",
                    "ok": False,
                    "pending_call": _v22_nonterminal_payload(sub, run)[
                        "pending_call"
                    ],
                },
            )
            return EVAL_EXIT_ENGINE_PAUSED
        _eval_json(sub, _v22_result_payload(sub, run, judge_mode="local-scripted-fixture"))
        return exit_code
    if args.command == "eval-status":
        state = sub.resume_evaluation_v22(run)
        _eval_json(
            sub,
            _v22_nonterminal_payload(sub, run)
            if state["terminal_status"] is None
            else _v22_result_payload(sub, run, judge_mode="status-only"),
        )
        return _eval_exit(sub, state, run)
    verification = sub.verify_evaluation_run(run)
    if not verification.valid:
        _eval_json(sub, {"ok": False, "issues": list(verification.issues)})
        return EVAL_EXIT_INTEGRITY
    state = sub.resume_evaluation_v22(run)
    _eval_json(
        sub,
        _v22_nonterminal_payload(sub, run)
        if state["terminal_status"] is None
        else _v22_result_payload(sub, run, judge_mode="verification-only"),
    )
    return _eval_exit(sub, state, run)


def _run_eval_command(args: argparse.Namespace) -> int:
    sub = _evaluation_substrate()
    run = _physical_eval_run_path(args.run)
    try:
        if args.command == "eval-init":
            if args.protocol == "2.2":
                if run.exists():
                    try:
                        with sub._open_run_storage(run) as storage:
                            nonempty = bool(storage.scan_inventory())
                            storage.assert_root_identity()
                    except sub.EvaluationIntegrityError:
                        raise
                    protocol = sub._v2_protocol(run) if nonempty else None
                    if nonempty and protocol is None:
                        raise sub.EvaluationIntegrityError("EVALUATION_RETAINED_RUN_INVALID")
                    if protocol in {"1.3", "2.0", "2.1"}:
                        verification = sub.verify_evaluation_run(run)
                        if not verification.valid:
                            raise sub.EvaluationIntegrityError("EVALUATION_RETAINED_RUN_INVALID")
                        raise PortableInputError(
                            "EVALUATION_LEGACY_READ_ONLY",
                            f"Protocol {protocol} evaluation runs are read-only.",
                        )
                gen = _generation_substrate()
                try:
                    case, capsule_paths = _portable_evaluation_case(
                        Path(args.case), substrate=sub, generation_substrate=gen
                    )
                    state = sub.initialize_evaluation_v22(
                        case,
                        run,
                        seed_hex=args.seed_hex,
                        generation_capsule_paths=capsule_paths,
                        generation_substrate=gen,
                    )
                except gen.GenerationIntegrityError as error:
                    raise _GenerationIntegrityError(gen.GENERATION_INTEGRITY_INVALID) from error
                except sub.EvaluationSourceParityUnprovenError as error:
                    raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
                _eval_json(sub, state)
                return EVAL_EXIT_SUCCESS
            if run.exists() and sub._v2_protocol(run) == "1.3":
                raise PortableInputError(
                    "EVALUATION_LEGACY_READ_ONLY",
                    "Protocol 1.3 evaluation runs are read-only.",
                )
            if run.exists():
                try:
                    with sub._open_run_storage(run, initialize=True):
                        pass
                except sub.EvaluationIntegrityError as error:
                    if str(error) == "run directory must be empty":
                        raise PortableInputError(
                            "EVALUATION_INPUT_INVALID", str(error)
                        ) from error
                    raise
            gen = _generation_substrate()
            try:
                case, capsule_paths = _portable_evaluation_case(
                    Path(args.case), substrate=sub, generation_substrate=gen
                )
            except PortableInputError as error:
                raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
            try:
                state = sub.initialize_evaluation(
                    case,
                    run,
                    seed_hex=args.seed_hex,
                    generation_capsule_paths=capsule_paths,
                    generation_substrate=gen,
                )
            except gen.GenerationIntegrityError as error:
                raise _GenerationIntegrityError(
                    gen.GENERATION_INTEGRITY_INVALID
                ) from error
            except sub.EvaluationSourceParityUnprovenError as error:
                raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
            _eval_json(sub, state)
            return EVAL_EXIT_SUCCESS
        protocol = sub._v2_protocol(run)
        if protocol in {None, "unknown"}:
            _write_error(
                "EVALUATION_PROTOCOL_UNSUPPORTED",
                "The evaluation run protocol is unsupported.",
            )
            return EVAL_EXIT_INPUT
        if protocol in {"invalid", "invalid-schema"} and args.command in {
            "eval-verify",
            "eval-resume",
        }:
            _eval_json(
                sub,
                {
                    "ok": False,
                    "issues": [
                        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"
                        if protocol == "invalid-schema"
                        else "EVALUATION_INTEGRITY_INVALID"
                    ],
                },
            )
            return EVAL_EXIT_INTEGRITY
        if protocol == "2.2":
            return _run_v22_eval_command(sub, args, run)
        if protocol == "2.1" and args.command == "eval-resume":
            _write_error(
                "EVALUATION_LEGACY_READ_ONLY",
                "Protocol 2.1 evaluation runs cannot use Protocol 2.2 resume.",
            )
            return EVAL_EXIT_INPUT
        if protocol in {"1.3", "2.0"} and args.command in {
            "eval-next",
            "eval-preflight",
            "eval-submit",
            "eval-submit-safe",
            "eval-stop-inconclusive",
            "eval-resume",
        }:
            _write_error(
                "EVALUATION_LEGACY_READ_ONLY",
                f"Protocol {protocol} evaluation runs are read-only.",
            )
            return EVAL_EXIT_INPUT
        if protocol == "2.1" and args.command == "eval-preflight":
            try:
                response = _portable_guarded_v2_response(sub, args, run)
                if response is None:
                    raise PortableInputError(
                        "EVALUATION_RESPONSE_INVALID", "The response is invalid."
                    )
                result = sub.preflight_judge_response(run, response)
            except (PortableInputError, sub.PortableEvaluationInputError):
                result = {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]}
            _eval_json(sub, result)
            return EVAL_EXIT_SUCCESS if result["valid"] else EVAL_EXIT_INPUT
        if protocol == "2.1" and args.command == "eval-submit-safe":
            guarded_response = _portable_guarded_v2_response(sub, args, run)
            if guarded_response is None:
                result = {
                    "accepted": False,
                    "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
                }
            else:
                result = sub.guarded_submit_judge_response(run, guarded_response)
            _eval_json(sub, result)
            return EVAL_EXIT_SUCCESS if result["accepted"] else EVAL_EXIT_INPUT
        if protocol == "2.1" and args.command == "eval-stop-inconclusive":
            if args.reason != "MECHANICAL_RESPONSE_INVALID":
                raise PortableInputError("INVALID_ARGUMENTS", "The terminal reason is unsupported.")
            state = sub.stop_evaluation_v21_inconclusive(run, args.reason)
            _eval_json(sub, state)
            return EVAL_EXIT_INCONCLUSIVE
        if args.command == "eval-next":
            request = sub.next_judge_request(run)
            if request is None:
                state = sub.resume_evaluation(run)
                _eval_json(sub, None)
                return _eval_exit(sub, state, run)
            _eval_json(sub, request)
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-preflight":
            request = sub.next_judge_request(run)
            if request is None:
                _eval_json(
                    sub,
                    sub._preflight_result(
                        None, code="EVALUATION_NO_PENDING_REQUEST"
                    ),
                )
                return EVAL_EXIT_INPUT
            try:
                response = _portable_eval_response(sub, Path(args.response))
                result = sub.preflight_judge_response(run, response)
            except PortableInputError as error:
                if error.code != "EVALUATION_RESPONSE_INVALID":
                    raise
                result = sub._preflight_result(
                    request, code="EVALUATION_RESPONSE_SCHEMA_INVALID"
                )
            except sub.PortableEvaluationInputError:
                result = sub._preflight_result(
                    request, code="EVALUATION_RESPONSE_SCHEMA_INVALID"
                )
            _eval_json(sub, result)
            return EVAL_EXIT_SUCCESS if result["ok"] else EVAL_EXIT_INPUT
        if args.command == "eval-submit":
            response = _portable_eval_response(sub, Path(args.response))
            request = sub.next_judge_request(run)
            if request is None or (
                response.get("operation") != request["operation"]
                or response.get("request_fingerprint") != request["request_fingerprint"]
            ):
                raise PortableInputError(
                    "EVALUATION_RESPONSE_INVALID", "The response does not bind the pending request."
                )
            state = sub.submit_judge_response(run, response)
            _eval_json(sub, state)
            return _eval_exit(sub, state, run)
        if args.command == "eval-submit-safe":
            request = sub.next_judge_request(run)
            if request is None:
                result = {
                    "schema_version": "1.0",
                    "accepted": False,
                    "preflight": sub._preflight_result(
                        None,
                        code="EVALUATION_NO_PENDING_REQUEST",
                    ),
                    "state": None,
                }
            else:
                guarded_response = _portable_guarded_eval_response(sub, Path(args.response))
                if guarded_response is None:
                    result = {
                        "schema_version": "1.0",
                        "accepted": False,
                        "preflight": sub._preflight_result(
                            request,
                            code="EVALUATION_RESPONSE_SCHEMA_INVALID",
                        ),
                        "state": None,
                    }
                else:
                    try:
                        result = sub.guarded_submit_judge_response(run, guarded_response)
                    except sub.PortableEvaluationInputError:
                        result = {
                            "schema_version": "1.0",
                            "accepted": False,
                            "preflight": sub._preflight_result(
                                request,
                                code="EVALUATION_RESPONSE_SCHEMA_INVALID",
                            ),
                            "state": None,
                        }
            _eval_json(sub, result)
            return EVAL_EXIT_SUCCESS if result["accepted"] else EVAL_EXIT_INPUT
        if args.command == "eval-status":
            state = sub.resume_evaluation(run)
            _eval_json(sub, state)
            return _eval_exit(sub, state, run)
        verification = sub.verify_evaluation_run(run)
        if not verification.valid:
            _eval_json(sub, {"ok": False, "issues": list(verification.issues)})
            return EVAL_EXIT_INTEGRITY
        state = sub.resume_evaluation(run)
        _eval_json(
            sub,
            {"ok": True, "manifest_root": verification.root_hash, "state": state},
        )
        return _eval_exit(sub, state, run)
    except sub.PortableEvaluationInputError as error:
        raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
    except sub.EvaluationSourceParityUnprovenError as error:
        _write_error("EVALUATION_SOURCE_PARITY_UNPROVEN", str(error))
        return EVAL_EXIT_INCONCLUSIVE
    except sub.EvaluationIntegrityError as error:
        raise _EvaluationIntegrityError(str(error)) from error


def _run_baseline_command(args: argparse.Namespace) -> int:
    """Run the report-blind portable baseline lifecycle."""
    sub = _evaluation_substrate()
    run = _physical_eval_run_path(args.run)
    try:
        if args.command == "eval-baseline-init":
            prior_values = getattr(args, "prior_baseline", None) or []
            if type(prior_values) is not list or any(
                type(value) is not str for value in prior_values
            ):
                raise PortableInputError(
                    "BASELINE_INPUT_INVALID", "The baseline ancestry is invalid."
                )
            prior_paths = tuple(_physical_eval_run_path(value) for value in prior_values)
            correction_value = getattr(args, "correction", None)
            sub.initialize_baseline_v1(
                Path(args.input),
                run,
                nonce_hex=args.nonce_hex,
                prior_baseline_path=prior_paths[-1] if prior_paths else None,
                correction_path=(
                    None if correction_value is None else Path(correction_value)
                ),
                prior_ancestry=prior_paths[:-1],
            )
            _eval_json(
                sub,
                sub.baseline_status_payload_v1(
                    run,
                    prior_baseline_path=prior_paths[-1] if prior_paths else None,
                    prior_ancestry=prior_paths[:-1],
                ),
            )
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-next":
            _eval_json(sub, sub.next_baseline_request_v1(run))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-submit-safe":
            payload = _portable_guarded_eval_response(sub, Path(args.response))
            result = sub.guarded_submit_baseline_response_v1(
                run,
                payload,
                provider_name=args.provider_name,
                model_name=args.model_name,
                judge_isolation=args.judge_isolation,
            )
            if not result["accepted"]:
                raise PortableInputError(
                    "BASELINE_EXTERNAL_RESPONSE_INVALID",
                    "The baseline response is invalid.",
                )
            _eval_json(sub, sub.baseline_status_payload_v1(run))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-status":
            _eval_json(sub, sub.baseline_status_payload_v1(run))
            return EVAL_EXIT_SUCCESS
        verification = sub.verify_baseline_run(run)
        _eval_json(
            sub,
            {
                "issues": list(verification["issues"]),
                "ok": verification["valid"],
                "protocol_version": "evaluation-baseline-v1",
            },
        )
        return EVAL_EXIT_SUCCESS if verification["valid"] else EVAL_EXIT_INTEGRITY
    except PortableInputError:
        raise
    except sub.BaselineInputError as error:
        raise PortableInputError(
            "BASELINE_INPUT_INVALID", "The baseline input is invalid."
        ) from error
    except sub.EvaluationIntegrityError as error:
        raise _EvaluationIntegrityError(str(error)) from error
    except (OSError, RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise PortableInputError(
            "BASELINE_INPUT_INVALID", "The baseline command input is invalid."
        ) from error


def _run_readiness_command(args: argparse.Namespace) -> int:
    """Run the dependency-free delivery-readiness companion."""
    sub = _evaluation_substrate()
    run = _physical_eval_run_path(args.run)

    def readiness_exit() -> int:
        status = sub.readiness_status_payload_v1(run)
        if status["delivery_readiness"] == "NOT_DELIVERABLE":
            return EVAL_EXIT_FAIL
        return EVAL_EXIT_SUCCESS

    try:
        if args.command == "eval-readiness-init":
            historical_run = getattr(args, "historical_v22_run", None)
            historical_label = getattr(args, "historical_report_label", None)
            if (historical_run is None) != (historical_label is None):
                raise PortableInputError(
                    "READINESS_INPUT_INVALID",
                    "Historical Protocol 2.2 options must be supplied together.",
                )
            sub.initialize_readiness_v1(
                run,
                baseline_run_dir=_physical_eval_run_path(args.baseline_run),
                qualification_run_dir=_physical_eval_run_path(args.qualification_run),
                generation_run_dir=_physical_eval_run_path(args.generation_run),
                validation_receipt_path=Path(args.validation_receipt),
                historical_v22_run_dir=(
                    None
                    if historical_run is None
                    else _physical_eval_run_path(historical_run)
                ),
                historical_anonymous_label=historical_label,
                generation_substrate=_generation_substrate(),
            )
        elif args.command == "eval-readiness-next":
            _eval_json(sub, sub.next_readiness_request_v1(run))
            return readiness_exit()
        elif args.command == "eval-readiness-submit-safe":
            value = _portable_guarded_eval_response(sub, Path(args.response))
            metadata = (
                getattr(args, "provider_name", None),
                getattr(args, "model_name", None),
                getattr(args, "judge_isolation", None),
            )
            response: object = value
            if any(item is not None for item in metadata):
                if value is None or any(item is None for item in metadata):
                    response = None
                else:
                    request = sub.next_readiness_request_v1(run)
                    if request is None:
                        response = None
                    else:
                        try:
                            response = sub.compile_readiness_draft_v1(
                                request,
                                value,
                                {
                                    "provider_name": metadata[0],
                                    "model_name": metadata[1],
                                    "judge_isolation": metadata[2],
                                },
                            )
                        except (sub.PortableEvaluationInputError, TypeError, ValueError):
                            response = None
            try:
                guarded = sub.guarded_submit_readiness_response_v1(run, response)
            except (sub.PortableEvaluationInputError, TypeError, ValueError):
                guarded = {"accepted": False}
            accepted = guarded.get("accepted") is True
            payload: dict[str, object] = {
                "accepted": accepted,
                "preflight": {
                    "diagnostics": (
                        [] if accepted else [sub.READINESS_EXTERNAL_RESPONSE_INVALID]
                    ),
                    "valid": accepted,
                },
            }
            if accepted:
                payload["status"] = sub.readiness_status_payload_v1(run)
            _eval_json(sub, payload)
            return readiness_exit() if accepted else EVAL_EXIT_INPUT
        elif args.command == "eval-readiness-status":
            _eval_json(sub, sub.readiness_status_payload_v1(run))
            return readiness_exit()
        else:
            verification = sub.verify_readiness_run_v1(run)
            _eval_json(sub, sub.readiness_verification_payload_v1(run, verification))
            return readiness_exit() if verification["valid"] else EVAL_EXIT_INTEGRITY
        _eval_json(sub, sub.readiness_status_payload_v1(run))
        return EVAL_EXIT_SUCCESS
    except PortableInputError:
        raise
    except sub.PortableEvaluationInputError as error:
        raise PortableInputError(
            "READINESS_INPUT_INVALID", "The readiness command input is invalid."
        ) from error
    except sub.EvaluationIntegrityError as error:
        raise _EvaluationIntegrityError(str(error)) from error


def _run_qualification_command(args: argparse.Namespace) -> int:
    sub = _evaluation_substrate()
    run = _physical_eval_run_path(args.run)
    try:
        if args.command == "eval-qualify-init":
            try:
                case = _portable_qualification_case(Path(args.case), substrate=sub)
            except (PortableInputError, sub.PortableEvaluationInputError) as error:
                raise PortableInputError(
                    "EVALUATION_INPUT_INVALID",
                    "The qualification case fixture is invalid.",
                ) from error
            payload = sub.initialize_case_qualification(
                case,
                run,
                nonce_hex=args.nonce_hex,
            )
        elif args.command == "eval-qualify-next":
            payload = sub.next_qualification_request(run)
        elif args.command == "eval-qualify-submit":
            request = sub.next_qualification_request(run)
            if request is None:
                payload = {
                    "schema_version": "1.0",
                    "accepted": False,
                    "preflight": sub._preflight_result(
                        None,
                        code="EVALUATION_NO_PENDING_REQUEST",
                    ),
                    "receipt": None,
                }
            else:
                response = _portable_guarded_eval_response(sub, Path(args.response))
                if response is None:
                    payload = {
                        "schema_version": "1.0",
                        "accepted": False,
                        "preflight": sub._preflight_result(
                            request,
                            code="EVALUATION_RESPONSE_SCHEMA_INVALID",
                        ),
                        "receipt": None,
                    }
                else:
                    payload = sub.guarded_submit_case_qualification(run, response)
            _eval_json(sub, payload)
            return EVAL_EXIT_SUCCESS if payload["accepted"] else EVAL_EXIT_INPUT
        elif args.command == "eval-qualify-status":
            payload = sub.resume_case_qualification(run)
        else:
            payload = sub.verify_case_qualification(run)
            _eval_json(sub, payload)
            return EVAL_EXIT_SUCCESS if payload["valid"] else EVAL_EXIT_INTEGRITY
        _eval_json(sub, payload)
        return EVAL_EXIT_SUCCESS
    except sub.PortableEvaluationInputError as error:
        raise PortableInputError("EVALUATION_INPUT_INVALID", str(error)) from error
    except sub.EvaluationIntegrityError as error:
        raise _EvaluationIntegrityError(str(error)) from error


def _run_generation_command(args: argparse.Namespace) -> int:
    sub = _generation_substrate()
    try:
        run = Path(args.run)
        if args.command == "eval-gen-init":
            payload = sub.initialize_generation(
                Path(args.input), run, nonce_hex=args.nonce_hex
            )
        elif args.command == "eval-gen-next":
            payload = sub.next_generation_request(run)
        elif args.command == "eval-gen-submit":
            payload = sub.submit_generation_response(run, Path(args.response))
        elif args.command == "eval-gen-status":
            payload = sub.generation_status(run)
        else:
            payload = sub.verify_generation_capsule(run)
        print(sub.canonical_json_bytes(payload).decode("utf-8"))
        return EVAL_EXIT_SUCCESS
    except sub.GenerationInputError as error:
        raise PortableInputError("GENERATION_INPUT_INVALID", str(error)) from error
    except sub.GenerationIntegrityError as error:
        code = (
            sub.GENERATION_STORAGE_PLATFORM_UNSUPPORTED
            if str(error).startswith(sub.GENERATION_STORAGE_PLATFORM_UNSUPPORTED)
            else sub.GENERATION_INTEGRITY_INVALID
        )
        raise _GenerationIntegrityError(code) from error


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command.startswith("eval-baseline-"):
            return _run_baseline_command(args)
        if args.command.startswith("eval-readiness-"):
            return _run_readiness_command(args)
        if args.command.startswith("eval-gen-"):
            return _run_generation_command(args)
        if args.command.startswith("eval-qualify-"):
            return _run_qualification_command(args)
        if args.command.startswith("eval-"):
            return _run_eval_command(args)
        if args.command == "prepare":
            matter = _matter_path(args.matter)
            receipt = prepare(Path(args.charter), matter)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        matter = _matter_path(args.matter, must_exist=True)
        receipt, status = finalize(
            matter,
            Path(args.draft),
            host_name=args.host,
            model_name=args.model,
        )
        print(json.dumps(receipt, sort_keys=True))
        return status
    except PortableInputError as error:
        _write_error(error.code, str(error))
        return 2
    except FileNotFoundError:
        _write_error("INPUT_NOT_FOUND", "A required input file was not found.")
        return 2
    except _EvaluationIntegrityError:
        _write_error("EVALUATION_INTEGRITY_INVALID", "The evaluation run failed integrity checks.")
        return EVAL_EXIT_INTEGRITY
    except _GenerationIntegrityError as error:
        _write_error(error.code, "The generation capsule failed integrity checks.")
        return EVAL_EXIT_INTEGRITY
    except Exception as error:
        _write_error(
            "ENGINE_FAILURE",
            f"The deterministic engine could not complete ({type(error).__name__}).",
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
