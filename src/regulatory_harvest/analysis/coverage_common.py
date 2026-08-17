"""Pure immutable indexes shared by proposition coverage evaluators."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeGuard

from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    ClaimKind,
    IssueCategory,
    SourceRecord,
)

from .build import build_analysis
from .drafts import AnalysisDraft, DraftGap

_ISSUE_CATEGORIES = frozenset(category.value for category in IssueCategory)


@dataclass(frozen=True)
class _Target:
    target_id: str
    source_id: str
    start_char: int
    end_char: int
    category: str | None = None


@dataclass(frozen=True)
class _CitationSpan:
    source_id: str
    start_char: int
    end_char: int


@dataclass(frozen=True)
class _ClaimRecord:
    kind: ClaimKind
    category: str | None
    spans: tuple[_CitationSpan, ...]


@dataclass(frozen=True)
class _GapRecord:
    code: str
    category: str
    source_ids: tuple[str, ...]


@dataclass(frozen=True)
class TargetIndexes:
    source_by_id: Mapping[str, SourceRecord]
    unit_objects: tuple[Mapping[str, object], ...]
    lead_objects: tuple[Mapping[str, object], ...]
    units: tuple[_Target, ...]
    leads: tuple[_Target, ...]
    declared_unit_ids: frozenset[str]
    declared_lead_ids: frozenset[str]
    unit_by_id: Mapping[str, _Target]
    lead_by_id: Mapping[str, _Target]


@dataclass(frozen=True)
class BriefBindingIndex:
    claim_locations: Mapping[str, tuple[str, ...]]
    atom_locations: Mapping[str, tuple[str, ...]]
    relationship_locations: Mapping[str, tuple[str, ...]]


ClaimRecord = _ClaimRecord
GapRecord = _GapRecord
Target = _Target
CitationSpan = _CitationSpan


def _issue(code: str, message: str, *related_ids: object) -> dict[str, object]:
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


def _append_issue(
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    code: str,
    message: str,
    *related_ids: object,
) -> None:
    issue = _issue(code, message, *related_ids)
    raw_ids = issue["related_ids"]
    safe_ids = tuple(str(value) for value in raw_ids) if isinstance(raw_ids, list) else ()
    key = (code, message, safe_ids)
    if key not in issue_keys:
        issue_keys.add(key)
        issues.append(issue)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _object_list(
    inventory: Mapping[str, object],
    key: str,
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[Mapping[str, object], ...]:
    raw_items = inventory.get(key)
    if not isinstance(raw_items, list):
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory collection is malformed.",
        )
        return ()
    if any(not isinstance(item, Mapping) for item in raw_items):
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory contains a malformed target.",
        )
    return tuple(
        MappingProxyType(dict(item)) for item in raw_items if isinstance(item, Mapping)
    )


def _check_count(
    inventory: Mapping[str, object],
    field: str,
    expected: int,
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    value = inventory.get(field)
    if not _is_int(value) or value != expected:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Prepared coverage inventory count is inconsistent.",
        )


def _source_index(
    sources: Sequence[SourceRecord],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> dict[str, SourceRecord]:
    validated_sources: list[SourceRecord] = []
    for source in sources:
        related_ids: tuple[str, ...] = ()
        try:
            if not isinstance(source, SourceRecord):
                raise TypeError("source row is not typed")
            payload = source.model_dump(mode="python", warnings=False)
            source_id = payload.get("source_id")
            if isinstance(source_id, str) and source_id.strip():
                related_ids = (source_id,)
            validated_sources.append(SourceRecord.model_validate(payload))
        except (AttributeError, TypeError, ValueError):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a malformed row.",
                *related_ids,
            )
    counts = Counter(source.source_id for source in validated_sources)
    for source_id, count in sorted(counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared sources contain a duplicate identifier.",
                source_id,
            )
    return {
        source.source_id: source
        for source in sorted(validated_sources, key=lambda item: item.source_id)
        if counts[source.source_id] == 1
    }


def _target_identity(item: Mapping[str, object], id_key: str) -> str | None:
    target_id = item.get(id_key)
    return target_id if isinstance(target_id, str) and target_id.strip() else None


def _unit_targets(
    unit_objects: Sequence[Mapping[str, object]],
    source_by_id: Mapping[str, SourceRecord],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[tuple[_Target, ...], frozenset[str]]:
    declared_ids = frozenset(
        target_id
        for item in unit_objects
        if (target_id := _target_identity(item, "unit_id")) is not None
    )
    id_counts = Counter(
        target_id
        for item in unit_objects
        if (target_id := _target_identity(item, "unit_id")) is not None
    )
    for target_id, count in sorted(id_counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared source units contain a duplicate identifier.",
                target_id,
            )

    targets: list[_Target] = []
    for item in unit_objects:
        unit_id = _target_identity(item, "unit_id")
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
            and _is_int(start)
            and _is_int(end)
            and 0 <= start < end <= len(source.normalized_text)
            and isinstance(excerpt, str)
            and excerpt == source.normalized_text[start:end]
            and item.get("coverage_required") is True
        )
        if not valid:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared source unit is malformed or is not an exact source slice.",
                unit_id,
                source_id,
            )
            continue
        assert unit_id is not None
        assert isinstance(source_id, str)
        assert isinstance(start, int) and not isinstance(start, bool)
        assert isinstance(end, int) and not isinstance(end, bool)
        targets.append(_Target(unit_id, source_id, start, end))
    return tuple(targets), declared_ids


def _lead_targets(
    lead_objects: Sequence[Mapping[str, object]],
    source_by_id: Mapping[str, SourceRecord],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[tuple[_Target, ...], frozenset[str]]:
    declared_ids = frozenset(
        target_id
        for item in lead_objects
        if (target_id := _target_identity(item, "lead_id")) is not None
    )
    id_counts = Counter(
        target_id
        for item in lead_objects
        if (target_id := _target_identity(item, "lead_id")) is not None
    )
    for target_id, count in sorted(id_counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared provision leads contain a duplicate identifier.",
                target_id,
            )

    targets: list[_Target] = []
    for item in lead_objects:
        lead_id = _target_identity(item, "lead_id")
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
            and _is_int(start)
            and _is_int(end)
            and 0 <= start < end <= len(source.normalized_text)
            and isinstance(excerpt, str)
            and excerpt == source.normalized_text[start:end]
            and isinstance(category, str)
            and category in _ISSUE_CATEGORIES
            and isinstance(topic, str)
            and bool(topic.strip())
            and isinstance(item.get("review_required"), bool)
        )
        if not valid:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Prepared provision lead is malformed or is not an exact source slice.",
                lead_id,
                source_id,
            )
            continue
        assert lead_id is not None
        assert isinstance(source_id, str)
        assert isinstance(start, int) and not isinstance(start, bool)
        assert isinstance(end, int) and not isinstance(end, bool)
        assert isinstance(category, str)
        targets.append(_Target(lead_id, source_id, start, end, category))
    return tuple(targets), declared_ids


def target_indexes(
    source_unit_inventory: Mapping[str, object],
    evidence_inventory: Mapping[str, object],
    sources: Sequence[SourceRecord],
) -> tuple[TargetIndexes, list[dict[str, object]]]:
    """Build validated source-unit and lead indexes without mutating inputs."""
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    source_by_id = _source_index(sources, issues=issues, issue_keys=issue_keys)
    unit_objects = _object_list(
        source_unit_inventory, "units", issues=issues, issue_keys=issue_keys
    )
    lead_objects = _object_list(
        evidence_inventory, "leads", issues=issues, issue_keys=issue_keys
    )
    _check_count(
        source_unit_inventory,
        "unit_count",
        len(unit_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    _check_count(
        source_unit_inventory,
        "required_unit_count",
        len(unit_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    _check_count(
        evidence_inventory,
        "lead_count",
        len(lead_objects),
        issues=issues,
        issue_keys=issue_keys,
    )
    units, declared_unit_ids = _unit_targets(
        unit_objects, source_by_id, issues=issues, issue_keys=issue_keys
    )
    leads, declared_lead_ids = _lead_targets(
        lead_objects, source_by_id, issues=issues, issue_keys=issue_keys
    )
    indexes = TargetIndexes(
        source_by_id=MappingProxyType(source_by_id),
        unit_objects=unit_objects,
        lead_objects=lead_objects,
        units=units,
        leads=leads,
        declared_unit_ids=declared_unit_ids,
        declared_lead_ids=declared_lead_ids,
        unit_by_id=MappingProxyType({target.target_id: target for target in units}),
        lead_by_id=MappingProxyType({target.target_id: target for target in leads}),
    )
    return indexes, issues


def claim_index(
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> tuple[dict[str, ClaimRecord], list[dict[str, object]]]:
    """Build exact, immutable claim records and bounded diagnostics."""
    try:
        built = build_analysis(draft, list(sources))
    except (AttributeError, KeyError, TypeError, ValueError):
        return {}, [
            _issue(
                "COVERAGE_ROW_INVALID",
                "The analysis draft could not be reconciled into exact evidence.",
            )
        ]

    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    issue_counts = Counter(issue.issue_id for issue in built.issues)
    category_by_issue: dict[str, str] = {}
    for issue in built.issues:
        if issue_counts[issue.issue_id] > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built analysis issues contain a duplicate identifier.",
                issue.issue_id,
            )
            continue
        category_by_issue[issue.issue_id] = issue.category.value

    citation_counts = Counter(citation.citation_id for citation in built.citations)
    citation_by_id = {
        citation.citation_id: citation
        for citation in built.citations
        if citation_counts[citation.citation_id] == 1
    }
    for citation_id, count in sorted(citation_counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built exact citations contain a duplicate identifier.",
                citation_id,
            )

    claim_counts = Counter(
        claim.claim_id for finding in built.findings for claim in finding.claims
    )
    for claim_id, count in sorted(claim_counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Built analysis claims contain a duplicate identifier.",
                claim_id,
            )

    claims: dict[str, ClaimRecord] = {}
    for finding in built.findings:
        category = category_by_issue.get(finding.issue_id)
        for claim in finding.claims:
            if claim_counts[claim.claim_id] != 1:
                continue
            spans = tuple(
                _CitationSpan(
                    source_id=citation.source_id,
                    start_char=citation.start_char,
                    end_char=citation.end_char,
                )
                for citation_id in claim.citation_ids
                if (citation := citation_by_id.get(citation_id)) is not None
            )
            claims[claim.claim_id] = _ClaimRecord(
                kind=claim.kind,
                category=category,
                spans=spans,
            )
    return claims, issues


def gap_index(
    draft: AnalysisDraft,
) -> tuple[dict[str, GapRecord], list[dict[str, object]]]:
    """Build immutable authored-gap records and bounded diagnostics."""
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    raw_gaps = draft.gaps
    if not isinstance(raw_gaps, list):
        return {}, [
            _issue(
                "COVERAGE_GAP_INVALID",
                "The authored gap ledger is malformed.",
            )
        ]

    gaps: list[DraftGap] = []
    for gap in raw_gaps:
        related_ids: tuple[str, ...] = ()
        try:
            if not isinstance(gap, DraftGap):
                raise TypeError("gap row is not typed")
            payload = gap.model_dump(mode="python", warnings=False)
            code = payload.get("code")
            if isinstance(code, str) and code.strip():
                related_ids = (code,)
            gaps.append(DraftGap.model_validate(payload))
        except (AttributeError, TypeError, ValueError):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_GAP_INVALID",
                "The authored gap ledger contains a malformed row.",
                *related_ids,
            )

    gap_counts = Counter(gap.code for gap in gaps)
    for gap_code, count in sorted(gap_counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_GAP_INVALID",
                "Authored gaps contain a duplicate mapping code.",
                gap_code,
            )
    return (
        {
            gap.code: _GapRecord(
                code=gap.code,
                category=gap.category.value,
                source_ids=tuple(gap.source_ids),
            )
            for gap in gaps
            if gap_counts[gap.code] == 1
        },
        issues,
    )


def _binding_values(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return ()
    return tuple(value)


def _add_bindings(
    locations: dict[str, dict[str, list[str]]],
    binding: object,
    path: str,
) -> None:
    for label, field_name in (
        ("claim", "claim_ids"),
        ("atom", "atom_ids"),
        ("relationship", "relationship_ids"),
    ):
        for identifier in _binding_values(getattr(binding, field_name, None)):
            if path not in locations[label][identifier]:
                locations[label][identifier].append(path)


def _walk_brief_block(
    block: object,
    path: str,
    locations: dict[str, dict[str, list[str]]],
) -> None:
    if not isinstance(block, BriefBlock):
        return
    if block.purpose is not BriefBlockPurpose.LEGAL_ANALYSIS:
        return
    if block.kind is BriefBlockKind.PARAGRAPH:
        _add_bindings(locations, block, path)
        return
    if block.kind in {BriefBlockKind.BULLET_LIST, BriefBlockKind.NUMBERED_LIST}:
        if not isinstance(block.items, list):
            return
        for index, item in enumerate(block.items):
            _add_bindings(locations, item, f"{path}.items[{index}]")
        return
    if block.kind is not BriefBlockKind.TABLE or not isinstance(block.rows, list):
        return
    for index, row in enumerate(block.rows):
        _add_bindings(locations, row, f"{path}.rows[{index}]")


def _frozen_locations(
    values: Mapping[str, list[str]],
) -> Mapping[str, tuple[str, ...]]:
    return MappingProxyType(
        {
            identifier: tuple(sorted(paths))
            for identifier, paths in sorted(values.items())
        }
    )


def brief_binding_index(brief: AttorneyBrief | None) -> BriefBindingIndex:
    """Index visible legal-analysis claim, atom, and relationship bindings."""
    locations: dict[str, dict[str, list[str]]] = {
        "claim": defaultdict(list),
        "atom": defaultdict(list),
        "relationship": defaultdict(list),
    }
    if brief is not None:
        try:
            brief = AttorneyBrief.model_validate(
                brief.model_dump(mode="python", warnings=False)
            )
        except (AttributeError, TypeError, ValueError):
            brief = None
    if brief is not None:
        executive_summary = getattr(brief, "executive_summary", None)
        if isinstance(executive_summary, list):
            for block_index, block in enumerate(executive_summary):
                _walk_brief_block(
                    block,
                    f"brief.executive_summary[{block_index}]",
                    locations,
                )
        sections = getattr(brief, "sections", None)
        if isinstance(sections, list):
            for section_index, section in enumerate(sections):
                section_path = f"brief.sections[{section_index}]"
                blocks = getattr(section, "blocks", None)
                if isinstance(blocks, list):
                    for block_index, block in enumerate(blocks):
                        _walk_brief_block(
                            block,
                            f"{section_path}.blocks[{block_index}]",
                            locations,
                        )
                subsections = getattr(section, "subsections", None)
                if not isinstance(subsections, list):
                    continue
                for subsection_index, subsection in enumerate(subsections):
                    subsection_path = (
                        f"{section_path}.subsections[{subsection_index}]"
                    )
                    subsection_blocks = getattr(subsection, "blocks", None)
                    if not isinstance(subsection_blocks, list):
                        continue
                    for block_index, block in enumerate(subsection_blocks):
                        _walk_brief_block(
                            block,
                            f"{subsection_path}.blocks[{block_index}]",
                            locations,
                        )
    return BriefBindingIndex(
        claim_locations=_frozen_locations(locations["claim"]),
        atom_locations=_frozen_locations(locations["atom"]),
        relationship_locations=_frozen_locations(locations["relationship"]),
    )


def span_overlaps_target(span: _CitationSpan, target: _Target) -> bool:
    """Return whether a citation and target overlap as half-open intervals."""
    return (
        span.source_id == target.source_id
        and span.start_char < target.end_char
        and target.start_char < span.end_char
    )
