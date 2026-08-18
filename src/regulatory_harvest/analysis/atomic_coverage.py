"""Fail-closed reconciliation of v2 source-unit and provision-lead reviews."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from pydantic import BaseModel

from regulatory_harvest.models import (
    AtomMateriality,
    AtomRelationshipType,
    AttorneyBrief,
    ClaimKind,
    CoverageElementStatus,
    FetchStatus,
    IssueCategory,
    LeadDispositionV2,
    LeadReviewDisposition,
    PropositionType,
    SourceQuality,
    SourceRecord,
    SourceRole,
    UnitDimensionDisposition,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .coverage import evaluate_provision_recall
from .coverage_common import (
    BriefBindingIndex,
    ClaimRecord,
    GapRecord,
    Target,
    TargetIndexes,
    brief_binding_index,
    claim_index,
    gap_index,
    span_overlaps_target,
    target_indexes,
)
from .drafts import (
    AnalysisDraft,
    DraftLeadDispositionV2,
    DraftLeadReview,
    DraftRuleAtom,
    DraftRuleAtomElements,
    DraftRuleRelationship,
    DraftUnitReview,
    DraftUnitReviewDimensions,
)
from .inventory import (
    MAX_PRIORITY_LEADS_PER_TOPIC,
    PROVISION_LEADS_NOTICE,
    PROVISION_LEADS_VERSION,
)
from .source_units import SOURCE_UNIT_INVENTORY_VERSION

ATOMIC_COVERAGE_CONTRACT_VERSION = "proposition-coverage-v2"
ATOMIC_TARGET_REVIEW_SCHEMA_VERSION = "1.0"
ATOMIC_RULE_GRAPH_SCHEMA_VERSION = "1.0"

_DIMENSION_NAMES = tuple(DraftUnitReviewDimensions.model_fields)
_ModelT = TypeVar("_ModelT", bound=BaseModel)

_REQUIRED_ELEMENTS: Mapping[PropositionType, tuple[str, ...]] = MappingProxyType(
    {
        PropositionType.STATUS: ("object",),
        PropositionType.DEFINITION: ("defined_term", "defined_meaning"),
        PropositionType.SCOPE: ("actor", "object"),
        PropositionType.DUTY: ("actor", "modality", "operative_action", "object"),
        PropositionType.PROHIBITION: (
            "actor",
            "modality",
            "operative_action",
            "object",
        ),
        PropositionType.RIGHT: ("actor", "modality", "operative_action", "object"),
        PropositionType.EXCEPTION: ("exception",),
        PropositionType.DEADLINE: ("timing",),
        PropositionType.ENFORCEMENT_TRIGGER: ("trigger",),
        PropositionType.ENFORCEMENT_ROUTE: ("authority", "route"),
        PropositionType.REMEDY: ("consequence",),
        PropositionType.PENALTY: ("consequence",),
        PropositionType.APPEAL: ("route",),
        PropositionType.IMPLEMENTATION: ("operative_action", "object"),
        PropositionType.OTHER: ("object",),
    }
)

_REQUIRED_RELATIONSHIPS: Mapping[PropositionType, tuple[AtomRelationshipType, ...]] = (
    MappingProxyType(
        {
            PropositionType.EXCEPTION: (AtomRelationshipType.EXCEPTION_TO,),
            PropositionType.DEADLINE: (AtomRelationshipType.DEADLINE_FOR,),
            PropositionType.ENFORCEMENT_TRIGGER: (AtomRelationshipType.TRIGGERED_BY,),
            PropositionType.ENFORCEMENT_ROUTE: (AtomRelationshipType.ENFORCES,),
            PropositionType.REMEDY: (
                AtomRelationshipType.TRIGGERED_BY,
                AtomRelationshipType.CONSEQUENCE_OF,
            ),
            PropositionType.PENALTY: (
                AtomRelationshipType.TRIGGERED_BY,
                AtomRelationshipType.CONSEQUENCE_OF,
            ),
            PropositionType.APPEAL: (AtomRelationshipType.APPEALS_FROM,),
        }
    )
)

_ACYCLIC_RELATIONSHIPS = frozenset(
    {
        AtomRelationshipType.EXCEPTION_TO,
        AtomRelationshipType.DEADLINE_FOR,
        AtomRelationshipType.TRIGGERED_BY,
        AtomRelationshipType.CONSEQUENCE_OF,
        AtomRelationshipType.APPEALS_FROM,
    }
)


@dataclass(frozen=True)
class _InvalidTarget:
    target_id: str
    source_id: str | None
    start_char: int | None
    end_char: int | None
    category: str | None = None
    review_required: bool | None = None


@dataclass(frozen=True)
class _GraphRows:
    raw_count: int
    valid_by_id: Mapping[str, BaseModel]
    invalid_ids: frozenset[str]

    @property
    def declared_ids(self) -> frozenset[str]:
        return frozenset((*self.valid_by_id, *self.invalid_ids))


def _issue(code: str, message: str, *related_ids: object) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "related_ids": sorted(
            {value for value in related_ids if isinstance(value, str) and value.strip()}
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
    if key in issue_keys:
        return
    issue_keys.add(key)
    issues.append(issue)


def _extend_index_issues(
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    incoming: Sequence[Mapping[str, object]],
    *,
    code: str,
) -> None:
    for issue in incoming:
        message = issue.get("message")
        related_ids = issue.get("related_ids")
        _append_issue(
            issues,
            issue_keys,
            code,
            message if isinstance(message, str) else "A shared coverage index is malformed.",
            *(related_ids if isinstance(related_ids, list) else []),
        )


def _empty_target_indexes() -> TargetIndexes:
    return TargetIndexes(
        source_by_id=MappingProxyType({}),
        unit_objects=(),
        lead_objects=(),
        units=(),
        leads=(),
        declared_unit_ids=frozenset(),
        declared_lead_ids=frozenset(),
        unit_by_id=MappingProxyType({}),
        lead_by_id=MappingProxyType({}),
    )


def _validated_rows(
    value: object,
    model_type: type[_ModelT],
    *,
    label: str,
    identifier_field: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    invalid_identifiers: set[str] | None = None,
) -> list[_ModelT]:
    if not isinstance(value, list):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            f"The atomic {label} collection is malformed.",
        )
        return []

    rows: list[_ModelT] = []
    for row in value:
        related_ids: tuple[str, ...] = ()
        payload: Mapping[str, object] = {}
        try:
            if isinstance(row, BaseModel):
                dumped = row.model_dump(mode="python", warnings=False)
                if isinstance(dumped, Mapping):
                    payload = dumped
            elif isinstance(row, Mapping):
                payload = row
            raw_identifier = payload.get(identifier_field)
            identifier = _optional_identifier(raw_identifier)
            if identifier is not None:
                related_ids = (identifier,)
            if not isinstance(row, model_type):
                raise TypeError("row is not the required typed model")
            rows.append(model_type.model_validate(dict(payload)))
        except (AttributeError, TypeError, ValueError):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                f"The atomic {label} collection contains a malformed row.",
                *related_ids,
            )
            if invalid_identifiers is not None and related_ids:
                invalid_identifiers.add(related_ids[0])
    return rows


def _unique_rows(
    rows: Sequence[_ModelT],
    *,
    identifier_field: str,
    label: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> dict[str, _ModelT]:
    identifiers = [str(getattr(row, identifier_field)) for row in rows]
    counts = Counter(identifiers)
    for identifier, count in sorted(counts.items()):
        if count > 1:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                f"Atomic {label} identifiers must be unique.",
                identifier,
            )
    return {
        identifier: row
        for identifier, row in sorted(zip(identifiers, rows, strict=True), key=lambda item: item[0])
        if counts[identifier] == 1
    }


def _related_issue(issues: Sequence[Mapping[str, object]], identifier: str) -> bool:
    return any(
        isinstance((related_ids := issue.get("related_ids")), list) and identifier in related_ids
        for issue in issues
    )


def _issue_has_related_ids(issue: Mapping[str, object], *identifiers: str) -> bool:
    related_ids = issue.get("related_ids")
    return isinstance(related_ids, list) and all(
        identifier in related_ids for identifier in identifiers
    )


def _issue_sort_ids(issue: Mapping[str, object]) -> tuple[str, ...]:
    related_ids = issue.get("related_ids")
    if not isinstance(related_ids, list):
        return ()
    return tuple(str(value) for value in related_ids)


def _review_inventory_versions(
    source_unit_inventory: object,
    evidence_inventory: object,
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> tuple[Mapping[str, object], Mapping[str, object], object, object]:
    if not isinstance(source_unit_inventory, Mapping):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The prepared source-unit inventory is malformed.",
        )
        safe_units: Mapping[str, object] = {}
    else:
        safe_units = source_unit_inventory
    if not isinstance(evidence_inventory, Mapping):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The prepared provision-lead inventory is malformed.",
        )
        safe_leads: Mapping[str, object] = {}
    else:
        safe_leads = evidence_inventory

    unit_version = safe_units.get("inventory_version")
    lead_version = safe_leads.get("inventory_version")
    if unit_version != SOURCE_UNIT_INVENTORY_VERSION:
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The prepared source-unit inventory version is missing or mismatched.",
        )
    if lead_version != PROVISION_LEADS_VERSION:
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The prepared provision-lead inventory version is missing or mismatched.",
        )
    return safe_units, safe_leads, unit_version, lead_version


def _disposition_value(value: object) -> str:
    raw_value = getattr(value, "value", value)
    return raw_value if isinstance(raw_value, str) else str(raw_value)


def _optional_identifier(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _optional_offset(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _invalid_targets(
    objects: Sequence[Mapping[str, object]],
    *,
    identifier_field: str,
    valid_ids: frozenset[str],
) -> tuple[_InvalidTarget, ...]:
    candidates: dict[str, list[_InvalidTarget]] = {}
    for item in objects:
        target_id = _optional_identifier(item.get(identifier_field))
        if target_id is None or target_id in valid_ids:
            continue
        category = _optional_identifier(item.get("issue_category"))
        review_required = item.get("review_required")
        candidate = _InvalidTarget(
            target_id=target_id,
            source_id=_optional_identifier(item.get("source_id")),
            start_char=_optional_offset(item.get("start_char")),
            end_char=_optional_offset(item.get("end_char")),
            category=category,
            review_required=review_required if isinstance(review_required, bool) else None,
        )
        candidates.setdefault(target_id, []).append(candidate)

    def candidate_key(target: _InvalidTarget) -> tuple[object, ...]:
        return (
            target.source_id is None,
            target.source_id or "",
            target.start_char is None,
            target.start_char if target.start_char is not None else -1,
            target.end_char is None,
            target.end_char if target.end_char is not None else -1,
            target.category is None,
            target.category or "",
            target.review_required is None,
            target.review_required is True,
        )

    return tuple(
        min(rows, key=candidate_key)
        for _, rows in sorted(candidates.items())
    )


def _strict_metadata_equal(value: object, expected: object) -> bool:
    if isinstance(expected, int):
        return isinstance(value, int) and not isinstance(value, bool) and value == expected
    if isinstance(expected, str):
        return isinstance(value, str) and value == expected
    if not isinstance(expected, Mapping) or not isinstance(value, Mapping):
        return False
    return (
        all(isinstance(key, str) and key.strip() for key in value)
        and all(isinstance(count, int) and not isinstance(count, bool) for count in value.values())
        and dict(value) == dict(expected)
    )


def _validate_inventory_metadata(
    source_unit_inventory: Mapping[str, object],
    evidence_inventory: Mapping[str, object],
    targets: TargetIndexes,
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    eligible_source_count = sum(
        source.fetch_status is FetchStatus.SUCCEEDED
        and source.source_role is not SourceRole.COMMENTARY_ANALYSIS
        and source.source_quality is not SourceQuality.UNUSABLE
        for source in targets.source_by_id.values()
    )
    evidence_source_count = sum(
        source.fetch_status is FetchStatus.SUCCEEDED and bool(source.normalized_text)
        for source in targets.source_by_id.values()
    )
    topic_counts: Counter[str] = Counter()
    priority_topic_counts: Counter[str] = Counter()
    priority_lead_count = 0
    for lead in targets.lead_objects:
        topic = lead.get("topic")
        if isinstance(topic, str) and topic.strip():
            topic_counts[topic] += 1
            if lead.get("review_required") is True:
                priority_topic_counts[topic] += 1
        if lead.get("review_required") is True:
            priority_lead_count += 1

    expectations = (
        (
            source_unit_inventory,
            "eligible_source_count",
            eligible_source_count,
            "Prepared source-unit inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "source_count",
            evidence_source_count,
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "priority_lead_count",
            priority_lead_count,
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "priority_topic_counts",
            dict(sorted(priority_topic_counts.items())),
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "priority_cap_per_topic",
            MAX_PRIORITY_LEADS_PER_TOPIC,
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "topic_counts",
            dict(sorted(topic_counts.items())),
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
        (
            evidence_inventory,
            "notice",
            PROVISION_LEADS_NOTICE,
            "Prepared provision-lead inventory metadata is inconsistent.",
        ),
    )
    for inventory, field_name, expected, message in expectations:
        if not _strict_metadata_equal(inventory.get(field_name), expected):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                message,
                field_name,
            )
    if any(count > MAX_PRIORITY_LEADS_PER_TOPIC for count in priority_topic_counts.values()):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "Prepared provision-lead inventory metadata is inconsistent.",
            "priority_cap_per_topic",
        )


def evaluate_atomic_target_review(
    source_unit_inventory: Mapping[str, object],
    evidence_inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, object]:
    """Reconcile every v2 source-unit dimension and every provision lead."""
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    safe_units, safe_leads, unit_version, lead_version = _review_inventory_versions(
        source_unit_inventory,
        evidence_inventory,
        issues=issues,
        issue_keys=issue_keys,
    )
    try:
        targets, target_issues = target_indexes(safe_units, safe_leads, sources)
    except (AttributeError, KeyError, TypeError, ValueError):
        targets = _empty_target_indexes()
        target_issues = []
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The prepared target inventories could not be indexed safely.",
        )
    _extend_index_issues(
        issues,
        issue_keys,
        target_issues,
        code="ATOMIC_REVIEW_INVALID",
    )
    _validate_inventory_metadata(
        safe_units,
        safe_leads,
        targets,
        issues=issues,
        issue_keys=issue_keys,
    )
    invalid_units = _invalid_targets(
        targets.unit_objects,
        identifier_field="unit_id",
        valid_ids=frozenset(targets.unit_by_id),
    )
    invalid_leads = _invalid_targets(
        targets.lead_objects,
        identifier_field="lead_id",
        valid_ids=frozenset(targets.lead_by_id),
    )

    if not isinstance(draft, AnalysisDraft):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_REVIEW_INVALID",
            "The atomic analysis draft is malformed.",
        )
        unit_review_value: object = None
        lead_review_value: object = None
        atom_value: object = None
        gap_by_code: Mapping[str, object] = {}
    else:
        if getattr(draft, "coverage_contract_version", None) != ATOMIC_COVERAGE_CONTRACT_VERSION:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                "The draft atomic coverage contract is missing or mismatched.",
            )
        if getattr(draft, "coverage_contract_version", None) == (
            ATOMIC_COVERAGE_CONTRACT_VERSION
        ) and not (
            isinstance(getattr(draft, "lead_reviews", None), list)
            and not draft.lead_reviews
            and isinstance(getattr(draft, "proposition_coverage", None), list)
            and not draft.proposition_coverage
        ):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REVIEW_INVALID",
                "A proposition-coverage-v2 draft cannot include legacy "
                "lead_reviews or proposition_coverage rows.",
            )
        unit_review_value = getattr(draft, "unit_reviews", None)
        lead_review_value = getattr(draft, "lead_dispositions_v2", None)
        atom_value = getattr(draft, "rule_atoms", None)
        try:
            gap_by_code, gap_issues = gap_index(draft)
        except (AttributeError, KeyError, TypeError, ValueError):
            gap_by_code = {}
            gap_issues = []
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_GAP_INVALID",
                "The authored atomic gap ledger could not be indexed safely.",
            )
        _extend_index_issues(
            issues,
            issue_keys,
            gap_issues,
            code="ATOMIC_GAP_INVALID",
        )

    unit_reviews = _validated_rows(
        unit_review_value,
        DraftUnitReview,
        label="unit review",
        identifier_field="unit_id",
        issues=issues,
        issue_keys=issue_keys,
    )
    lead_reviews = _validated_rows(
        lead_review_value,
        DraftLeadDispositionV2,
        label="lead disposition",
        identifier_field="lead_id",
        issues=issues,
        issue_keys=issue_keys,
    )
    invalid_atom_ids: set[str] = set()
    atoms = _validated_rows(
        atom_value,
        DraftRuleAtom,
        label="rule atom",
        identifier_field="atom_id",
        issues=issues,
        issue_keys=issue_keys,
        invalid_identifiers=invalid_atom_ids,
    )
    unit_review_by_id = _unique_rows(
        unit_reviews,
        identifier_field="unit_id",
        label="unit review",
        issues=issues,
        issue_keys=issue_keys,
    )
    lead_review_by_id = _unique_rows(
        lead_reviews,
        identifier_field="lead_id",
        label="lead disposition",
        issues=issues,
        issue_keys=issue_keys,
    )
    atom_by_id = _unique_rows(
        atoms,
        identifier_field="atom_id",
        label="rule atom",
        issues=issues,
        issue_keys=issue_keys,
    )
    invalid_atom_ids.update(
        identifier
        for identifier, count in Counter(atom.atom_id for atom in atoms).items()
        if count > 1
    )
    invalid_unit_atom_refs: set[tuple[str, str]] = set()
    invalid_lead_atom_refs: set[str] = set()

    for unit_id in sorted(unit_review_by_id):
        if unit_id not in targets.declared_unit_ids:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_TARGET_UNKNOWN",
                "A unit review references a unit outside the prepared inventory.",
                unit_id,
            )
    for lead_id in sorted(lead_review_by_id):
        if lead_id not in targets.declared_lead_ids:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_TARGET_UNKNOWN",
                "A lead disposition references a lead outside the prepared inventory.",
                lead_id,
            )

    for atom_id, atom in atom_by_id.items():
        for unit_id in atom.unit_ids:
            if unit_id not in targets.declared_unit_ids:
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_TARGET_UNKNOWN",
                    "A rule atom references a unit outside the prepared inventory.",
                    atom_id,
                    unit_id,
                )
        for lead_id in atom.lead_ids:
            if lead_id not in targets.declared_lead_ids:
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_TARGET_UNKNOWN",
                    "A rule atom references a lead outside the prepared inventory.",
                    atom_id,
                    lead_id,
                )

    for target in targets.units:
        unit_review = unit_review_by_id.get(target.target_id)
        if unit_review is None:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_UNIT_REVIEW_UNRESOLVED",
                "Required source unit has no complete nine-dimension review.",
                target.target_id,
            )
            continue
        for dimension_name in _DIMENSION_NAMES:
            dimension = getattr(unit_review.dimensions, dimension_name)
            if dimension.disposition is UnitDimensionDisposition.MAPPED:
                for atom_id in dimension.atom_ids:
                    mapped_atom = atom_by_id.get(atom_id)
                    if mapped_atom is None and atom_id in invalid_atom_ids:
                        invalid_unit_atom_refs.add((target.target_id, dimension_name))
                    elif mapped_atom is None or target.target_id not in mapped_atom.unit_ids:
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_REVIEW_INVALID",
                            "A mapped unit dimension lacks a reciprocal rule-atom target.",
                            target.target_id,
                            dimension_name,
                            atom_id,
                        )
            elif dimension.disposition is UnitDimensionDisposition.GAP:
                for gap_code in dimension.gap_codes:
                    gap = gap_by_code.get(gap_code)
                    source_ids = getattr(gap, "source_ids", ())
                    if (
                        gap is None
                        or len(source_ids) != len(set(source_ids))
                        or set(source_ids) != {target.source_id}
                    ):
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_GAP_INVALID",
                            "A unit-dimension gap must be unique, authored, and source-bound.",
                            target.target_id,
                            dimension_name,
                            gap_code,
                        )

    for target in targets.leads:
        lead_review = lead_review_by_id.get(target.target_id)
        if lead_review is None:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_LEAD_REVIEW_UNRESOLVED",
                "Provision lead has no atomic disposition.",
                target.target_id,
            )
            continue
        if lead_review.disposition is LeadDispositionV2.MAPPED:
            for atom_id in lead_review.atom_ids:
                mapped_atom = atom_by_id.get(atom_id)
                if mapped_atom is None and atom_id in invalid_atom_ids:
                    invalid_lead_atom_refs.add(target.target_id)
                elif mapped_atom is None or target.target_id not in mapped_atom.lead_ids:
                    _append_issue(
                        issues,
                        issue_keys,
                        "ATOMIC_REVIEW_INVALID",
                        "A mapped lead disposition lacks a reciprocal rule-atom target.",
                        target.target_id,
                        atom_id,
                    )
        elif lead_review.disposition is LeadDispositionV2.GAP:
            for gap_code in lead_review.gap_codes:
                gap = gap_by_code.get(gap_code)
                source_ids = getattr(gap, "source_ids", ())
                category = getattr(gap, "category", None)
                if (
                    gap is None
                    or len(source_ids) != len(set(source_ids))
                    or set(source_ids) != {target.source_id}
                    or category != target.category
                ):
                    _append_issue(
                        issues,
                        issue_keys,
                        "ATOMIC_GAP_INVALID",
                        "A lead gap must be unique, authored, source-bound, and category-matched.",
                        target.target_id,
                        gap_code,
                    )

    for atom_id, atom in atom_by_id.items():
        for unit_id in atom.unit_ids:
            reciprocal_unit_review = unit_review_by_id.get(unit_id)
            if reciprocal_unit_review is not None and any(
                dimension.disposition is UnitDimensionDisposition.MAPPED
                and atom_id in dimension.atom_ids
                for dimension in (
                    getattr(reciprocal_unit_review.dimensions, name) for name in _DIMENSION_NAMES
                )
            ):
                continue
            if unit_id in targets.unit_by_id:
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_REVIEW_INVALID",
                    "A rule atom unit target lacks a reciprocal mapped dimension.",
                    atom_id,
                    unit_id,
                )
        for lead_id in atom.lead_ids:
            reciprocal_lead_review = lead_review_by_id.get(lead_id)
            if (
                reciprocal_lead_review is not None
                and reciprocal_lead_review.disposition is LeadDispositionV2.MAPPED
                and atom_id in reciprocal_lead_review.atom_ids
            ):
                continue
            if lead_id in targets.lead_by_id:
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_REVIEW_INVALID",
                    "A rule atom lead target lacks a reciprocal mapped disposition.",
                    atom_id,
                    lead_id,
                )

    issues.sort(
        key=lambda issue: (
            str(issue["code"]),
            _issue_sort_ids(issue),
            str(issue["message"]),
        )
    )

    unit_results: list[dict[str, object]] = []
    unit_dispositions: Counter[str] = Counter()
    for target in sorted(
        targets.units,
        key=lambda item: (
            item.source_id,
            item.start_char,
            item.end_char,
            item.target_id,
        ),
    ):
        unit_review = unit_review_by_id.get(target.target_id)
        unit_valid = unit_review is not None and not _related_issue(
            issues, target.target_id
        )
        dimensions: dict[str, object] = {}
        for dimension_name in _DIMENSION_NAMES:
            if unit_review is None:
                disposition = "unresolved"
                atom_ids: list[str] = []
                gap_codes: list[str] = []
                rationale = None
                dimension_valid = False
            else:
                dimension = getattr(unit_review.dimensions, dimension_name)
                disposition = _disposition_value(dimension.disposition)
                atom_ids = sorted(dimension.atom_ids)
                gap_codes = sorted(dimension.gap_codes)
                rationale = dimension.rationale
                dimension_valid = not any(
                    _issue_has_related_ids(issue, target.target_id, dimension_name)
                    for issue in issues
                ) and (target.target_id, dimension_name) not in invalid_unit_atom_refs
            unit_dispositions[disposition] += 1
            dimensions[dimension_name] = {
                "disposition": disposition,
                "atom_ids": atom_ids,
                "gap_codes": gap_codes,
                "rationale": rationale,
                "valid": dimension_valid,
            }
            unit_valid = unit_valid and dimension_valid
        unit_results.append(
            {
                "unit_id": target.target_id,
                "source_id": target.source_id,
                "target_state": "valid",
                "dimensions": dimensions,
                "valid": unit_valid,
            }
        )
    for invalid_target in invalid_units:
        unit_dispositions["invalid"] += len(_DIMENSION_NAMES)
        unit_results.append(
            {
                "unit_id": invalid_target.target_id,
                "source_id": invalid_target.source_id,
                "target_state": "invalid",
                "dimensions": {
                    dimension_name: {
                        "disposition": "invalid",
                        "atom_ids": [],
                        "gap_codes": [],
                        "rationale": None,
                        "valid": False,
                    }
                    for dimension_name in _DIMENSION_NAMES
                },
                "valid": False,
            }
        )
    unit_order = {
        target.target_id: (
            target.source_id,
            target.start_char,
            target.end_char,
            target.target_id,
        )
        for target in targets.units
    }
    unit_order.update(
        {
            target.target_id: (
                target.source_id or "",
                target.start_char if target.start_char is not None else -1,
                target.end_char if target.end_char is not None else -1,
                target.target_id,
            )
            for target in invalid_units
        }
    )
    unit_results.sort(key=lambda row: unit_order[str(row["unit_id"])])

    lead_priority = {
        target_id: item.get("review_required")
        for item in targets.lead_objects
        if isinstance((target_id := item.get("lead_id")), str) and target_id in targets.lead_by_id
    }
    lead_results: list[dict[str, object]] = []
    lead_dispositions: Counter[str] = Counter()
    for target in sorted(
        targets.leads,
        key=lambda item: (
            item.source_id,
            item.start_char,
            item.end_char,
            item.target_id,
        ),
    ):
        lead_review = lead_review_by_id.get(target.target_id)
        if lead_review is None:
            disposition = "unresolved"
            atom_ids = []
            gap_codes = []
            rationale = None
        else:
            disposition = _disposition_value(lead_review.disposition)
            atom_ids = sorted(lead_review.atom_ids)
            gap_codes = sorted(lead_review.gap_codes)
            rationale = lead_review.rationale
        lead_dispositions[disposition] += 1
        lead_results.append(
            {
                "lead_id": target.target_id,
                "source_id": target.source_id,
                "target_state": "valid",
                "issue_category": target.category,
                "review_required": lead_priority.get(target.target_id),
                "disposition": disposition,
                "atom_ids": atom_ids,
                "gap_codes": gap_codes,
                "rationale": rationale,
                "valid": lead_review is not None
                and target.target_id not in invalid_lead_atom_refs
                and not _related_issue(issues, target.target_id),
            }
        )
    for invalid_target in invalid_leads:
        lead_dispositions["invalid"] += 1
        lead_results.append(
            {
                "lead_id": invalid_target.target_id,
                "source_id": invalid_target.source_id,
                "target_state": "invalid",
                "issue_category": invalid_target.category,
                "review_required": invalid_target.review_required,
                "disposition": "invalid",
                "atom_ids": [],
                "gap_codes": [],
                "rationale": None,
                "valid": False,
            }
        )
    lead_order = {
        target.target_id: (
            target.source_id,
            target.start_char,
            target.end_char,
            target.target_id,
        )
        for target in targets.leads
    }
    lead_order.update(
        {
            target.target_id: (
                target.source_id or "",
                target.start_char if target.start_char is not None else -1,
                target.end_char if target.end_char is not None else -1,
                target.target_id,
            )
            for target in invalid_leads
        }
    )
    lead_results.sort(key=lambda row: lead_order[str(row["lead_id"])])

    payload: dict[str, object] = {
        "schema_version": ATOMIC_TARGET_REVIEW_SCHEMA_VERSION,
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "inventory_versions": {
            "provision_leads": lead_version if isinstance(lead_version, str) else None,
            "source_units": unit_version if isinstance(unit_version, str) else None,
        },
        "valid": not issues,
        "target_counts": {
            "invalid_leads": len(invalid_leads),
            "invalid_units": len(invalid_units),
            "lead_rows": len(targets.lead_objects),
            "leads": len(lead_results),
            "unit_rows": len(targets.unit_objects),
            "units": len(unit_results),
        },
        "disposition_counts": {
            "lead_dispositions": {
                value: lead_dispositions[value]
                for value in ("gap", "invalid", "mapped", "not_material", "unresolved")
            },
            "unit_dimensions": {
                value: unit_dispositions[value]
                for value in (
                    "gap",
                    "invalid",
                    "mapped",
                    "not_material",
                    "not_present",
                    "unresolved",
                )
            },
        },
        "units": unit_results,
        "leads": lead_results,
        "issues": issues,
    }
    payload["target_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload


def _snapshot_graph_rows(
    value: object,
    model_type: type[_ModelT],
    *,
    identifier_field: str,
    label: str,
    issue_code: str,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> _GraphRows:
    if not isinstance(value, list):
        _append_issue(
            issues,
            issue_keys,
            issue_code,
            f"The atomic {label} collection is malformed.",
        )
        return _GraphRows(0, MappingProxyType({}), frozenset())

    candidates: dict[str, list[_ModelT | None]] = {}
    for row in value:
        payload: Mapping[str, object] = {}
        try:
            if isinstance(row, BaseModel):
                dumped = row.model_dump(mode="python", warnings=False)
                if isinstance(dumped, Mapping):
                    payload = dumped
            elif isinstance(row, Mapping):
                payload = row
            raw_identifier = payload.get(identifier_field)
            identifier = _optional_identifier(raw_identifier)
            if not isinstance(row, model_type):
                raise TypeError("row is not the required typed model")
            validated = model_type.model_validate(dict(payload))
        except (AttributeError, TypeError, ValueError):
            identifier = _optional_identifier(payload.get(identifier_field))
            _append_issue(
                issues,
                issue_keys,
                issue_code,
                f"The atomic {label} collection contains a malformed row.",
                identifier,
            )
            if identifier is not None:
                candidates.setdefault(identifier, []).append(None)
            continue
        validated_identifier = str(getattr(validated, identifier_field))
        candidates.setdefault(validated_identifier, []).append(validated)

    valid_by_id: dict[str, BaseModel] = {}
    invalid_ids: set[str] = set()
    for identifier, rows in sorted(candidates.items()):
        if len(rows) != 1:
            _append_issue(
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
            valid_by_id[identifier] = rows[0]
    return _GraphRows(
        raw_count=len(value),
        valid_by_id=MappingProxyType(valid_by_id),
        invalid_ids=frozenset(invalid_ids),
    )


def _is_requirement_like(atom: DraftRuleAtom) -> bool:
    return atom.proposition_type in {
        PropositionType.DUTY,
        PropositionType.PROHIBITION,
        PropositionType.RIGHT,
        PropositionType.SCOPE,
        PropositionType.IMPLEMENTATION,
        PropositionType.OTHER,
    } or atom.category is IssueCategory.REQUIREMENTS


def _relationship_categories_valid(
    relationship: DraftRuleRelationship,
    source: DraftRuleAtom,
    target: DraftRuleAtom,
) -> bool:
    relation_type = relationship.relation_type
    source_type = source.proposition_type
    target_type = target.proposition_type
    if relation_type is AtomRelationshipType.QUALIFIES:
        return source_type in {
            PropositionType.STATUS,
            PropositionType.SCOPE,
            PropositionType.OTHER,
        }
    if relation_type is AtomRelationshipType.EXCEPTION_TO:
        return source_type is PropositionType.EXCEPTION and _is_requirement_like(target)
    if relation_type is AtomRelationshipType.DEADLINE_FOR:
        return source_type is PropositionType.DEADLINE and target_type not in {
            PropositionType.STATUS,
            PropositionType.DEFINITION,
            PropositionType.DEADLINE,
        }
    if relation_type is AtomRelationshipType.ENFORCES:
        return source_type is PropositionType.ENFORCEMENT_ROUTE and _is_requirement_like(
            target
        )
    if relation_type is AtomRelationshipType.TRIGGERED_BY:
        return (
            source_type is PropositionType.ENFORCEMENT_TRIGGER
            and target_type in {PropositionType.DUTY, PropositionType.PROHIBITION}
        ) or (
            source_type in {PropositionType.REMEDY, PropositionType.PENALTY}
            and target_type is PropositionType.ENFORCEMENT_TRIGGER
        )
    if relation_type is AtomRelationshipType.CONSEQUENCE_OF:
        return source_type in {
            PropositionType.REMEDY,
            PropositionType.PENALTY,
        } and target_type in {PropositionType.DUTY, PropositionType.PROHIBITION}
    if relation_type is AtomRelationshipType.APPEALS_FROM:
        return source_type is PropositionType.APPEAL and target_type in {
            PropositionType.ENFORCEMENT_ROUTE,
            PropositionType.REMEDY,
            PropositionType.PENALTY,
        }
    return relation_type is AtomRelationshipType.DEFINES and source_type is (
        PropositionType.DEFINITION
    )


def _cyclic_atom_components(
    relationships: Sequence[DraftRuleRelationship],
) -> tuple[frozenset[str], ...]:
    adjacency: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for relationship in relationships:
        if relationship.relation_type not in _ACYCLIC_RELATIONSHIPS:
            continue
        source_id = relationship.source_atom_id
        target_id = relationship.target_atom_id
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
        component_stack = [root]
        assigned.add(root)
        while component_stack:
            node = component_stack.pop()
            component.add(node)
            for neighbor in sorted(reverse[node], reverse=True):
                if neighbor not in assigned:
                    assigned.add(neighbor)
                    component_stack.append(neighbor)
        if len(component) > 1:
            components.append(frozenset(component))
    return tuple(sorted(components, key=lambda component: tuple(sorted(component))))


def evaluate_rule_graph(draft: AnalysisDraft) -> dict[str, object]:
    """Validate the v2 atomic proposition and directed relationship graph."""
    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    if not isinstance(draft, AnalysisDraft):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_RULE_INVALID",
            "The atomic analysis draft is malformed.",
        )
        atom_value: object = None
        relationship_value: object = None
    else:
        if getattr(draft, "coverage_contract_version", None) != (
            ATOMIC_COVERAGE_CONTRACT_VERSION
        ):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_RULE_INVALID",
                "The draft atomic coverage contract is missing or mismatched.",
            )
        atom_value = getattr(draft, "rule_atoms", None)
        relationship_value = getattr(draft, "rule_relationships", None)

    atom_snapshots = _snapshot_graph_rows(
        atom_value,
        DraftRuleAtom,
        identifier_field="atom_id",
        label="rule atom",
        issue_code="ATOMIC_RULE_INVALID",
        issues=issues,
        issue_keys=issue_keys,
    )
    relationship_snapshots = _snapshot_graph_rows(
        relationship_value,
        DraftRuleRelationship,
        identifier_field="relationship_id",
        label="rule relationship",
        issue_code="ATOMIC_RELATIONSHIP_INVALID",
        issues=issues,
        issue_keys=issue_keys,
    )
    atoms = {
        identifier: row
        for identifier, row in atom_snapshots.valid_by_id.items()
        if isinstance(row, DraftRuleAtom)
    }
    relationships = {
        identifier: row
        for identifier, row in relationship_snapshots.valid_by_id.items()
        if isinstance(row, DraftRuleRelationship)
    }

    invalid_atom_ids = set(atom_snapshots.invalid_ids)
    for atom_id, atom in atoms.items():
        for element_name in _REQUIRED_ELEMENTS[atom.proposition_type]:
            element = getattr(atom.elements, element_name)
            if element.status is CoverageElementStatus.STATED:
                continue
            invalid_atom_ids.add(atom_id)
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_REQUIRED_ELEMENT_MISSING",
                "A rule atom is missing a required stated element.",
                atom_id,
                element_name,
            )

    invalid_relationship_ids = set(relationship_snapshots.invalid_ids)
    declared_atom_ids = atom_snapshots.declared_ids
    category_valid_relationship_ids: set[str] = set()
    cycle_candidates: list[DraftRuleRelationship] = []
    for relationship_id, relationship in relationships.items():
        unknown_ids = sorted(
            {
                endpoint
                for endpoint in (
                    relationship.source_atom_id,
                    relationship.target_atom_id,
                )
                if endpoint not in declared_atom_ids
            }
        )
        if unknown_ids:
            invalid_relationship_ids.add(relationship_id)
            for unknown_id in unknown_ids:
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_RELATIONSHIP_UNKNOWN",
                    "A rule relationship references an unknown atom.",
                    unknown_id,
                )
            continue

        source = atoms.get(relationship.source_atom_id)
        target = atoms.get(relationship.target_atom_id)
        if source is None or target is None:
            invalid_relationship_ids.add(relationship_id)
            continue
        if not _relationship_categories_valid(relationship, source, target):
            invalid_relationship_ids.add(relationship_id)
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_RELATIONSHIP_INVALID",
                "A rule relationship has an invalid direction or endpoint category.",
                relationship_id,
                relationship.source_atom_id,
                relationship.target_atom_id,
            )
        else:
            category_valid_relationship_ids.add(relationship_id)
            if relationship.relation_type in _ACYCLIC_RELATIONSHIPS:
                cycle_candidates.append(relationship)

    cyclic_components = _cyclic_atom_components(cycle_candidates)
    for component in cyclic_components:
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_RELATIONSHIP_INVALID",
            "Atomic rule relationships contain a prohibited cycle.",
            *component,
        )
        for relationship_id, relationship in relationships.items():
            if (
                relationship.relation_type in _ACYCLIC_RELATIONSHIPS
                and relationship.source_atom_id in component
                and relationship.target_atom_id in component
            ):
                invalid_relationship_ids.add(relationship_id)

    outgoing_types: dict[str, set[AtomRelationshipType]] = {}
    for relationship_id in sorted(category_valid_relationship_ids):
        relationship = relationships[relationship_id]
        outgoing_types.setdefault(relationship.source_atom_id, set()).add(
            relationship.relation_type
        )

    for atom_id, atom in atoms.items():
        if atom_id in invalid_atom_ids:
            continue
        alternatives = _REQUIRED_RELATIONSHIPS.get(atom.proposition_type, ())
        if alternatives and not outgoing_types.get(atom_id, set()).intersection(alternatives):
            invalid_atom_ids.add(atom_id)
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_RELATIONSHIP_REQUIRED",
                "A rule atom is missing a required valid outgoing relationship.",
                atom_id,
            )

    issues.sort(
        key=lambda issue: (
            str(issue["code"]),
            _issue_sort_ids(issue),
            str(issue["message"]),
        )
    )

    atom_results: list[dict[str, object]] = []
    for atom_id in sorted(atom_snapshots.declared_ids):
        result_atom = atoms.get(atom_id)
        if result_atom is None:
            atom_results.append(
                {
                    "atom_id": atom_id,
                    "row_state": "invalid",
                    "category": None,
                    "proposition_type": None,
                    "materiality": None,
                    "unit_ids": [],
                    "lead_ids": [],
                    "required_elements": [],
                    "stated_elements": [],
                    "required_relationship_types": [],
                    "valid": False,
                }
            )
            continue
        stated_elements = sorted(
            field_name
            for field_name in DraftRuleAtomElements.model_fields
            if getattr(result_atom.elements, field_name).status
            is CoverageElementStatus.STATED
        )
        atom_results.append(
            {
                "atom_id": atom_id,
                "row_state": "valid",
                "category": result_atom.category.value,
                "proposition_type": result_atom.proposition_type.value,
                "materiality": result_atom.materiality.value,
                "unit_ids": sorted(result_atom.unit_ids),
                "lead_ids": sorted(result_atom.lead_ids),
                "required_elements": sorted(
                    _REQUIRED_ELEMENTS[result_atom.proposition_type]
                ),
                "stated_elements": stated_elements,
                "required_relationship_types": sorted(
                    value.value
                    for value in _REQUIRED_RELATIONSHIPS.get(
                        result_atom.proposition_type, ()
                    )
                ),
                "valid": atom_id not in invalid_atom_ids,
            }
        )

    relationship_results: list[dict[str, object]] = []
    for relationship_id in sorted(relationship_snapshots.declared_ids):
        result_relationship = relationships.get(relationship_id)
        if result_relationship is None:
            relationship_results.append(
                {
                    "relationship_id": relationship_id,
                    "row_state": "invalid",
                    "relation_type": None,
                    "source_atom_id": None,
                    "target_atom_id": None,
                    "claim_ids": [],
                    "valid": False,
                }
            )
            continue
        relationship_results.append(
            {
                "relationship_id": relationship_id,
                "row_state": "valid",
                "relation_type": result_relationship.relation_type.value,
                "source_atom_id": result_relationship.source_atom_id,
                "target_atom_id": result_relationship.target_atom_id,
                "claim_ids": sorted(result_relationship.claim_ids),
                "valid": relationship_id not in invalid_relationship_ids,
            }
        )

    payload: dict[str, object] = {
        "schema_version": ATOMIC_RULE_GRAPH_SCHEMA_VERSION,
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "valid": not issues,
        "rule_counts": {
            "atom_rows": atom_snapshots.raw_count,
            "atoms": len(atom_results),
            "invalid_atoms": sum(not bool(row["valid"]) for row in atom_results),
            "relationship_rows": relationship_snapshots.raw_count,
            "relationships": len(relationship_results),
            "invalid_relationships": sum(
                not bool(row["valid"]) for row in relationship_results
            ),
        },
        "atoms": atom_results,
        "relationships": relationship_results,
        "issues": issues,
    }
    payload["rule_graph_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload


def _canonical_issues(
    issues: Sequence[Mapping[str, object]],
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
            str(issue["code"]),
            _issue_sort_ids(issue),
            str(issue["message"]),
        )
    )
    return canonical


def compose_atomic_coverage_review(
    *,
    target_review: Mapping[str, object],
    rule_graph: Mapping[str, object],
    counts: Mapping[str, int],
    issues: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Compose one canonical schema-3 review without mutating partial reviews."""
    canonical_counts = {
        key: value
        for key, value in sorted(counts.items())
        if isinstance(key, str)
        and key.strip()
        and isinstance(value, int)
        and not isinstance(value, bool)
    }
    canonical_issues = _canonical_issues(issues)
    payload: dict[str, object] = {
        "schema_version": "3.0",
        "coverage_contract_version": ATOMIC_COVERAGE_CONTRACT_VERSION,
        "valid": len(canonical_issues) == 0,
        "target_review": dict(target_review),
        "rule_graph": dict(rule_graph),
        "counts": canonical_counts,
        "issues": canonical_issues,
    }
    payload["coverage_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload


def _partial_review_issues(review: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw_issues = review.get("issues")
    if not isinstance(raw_issues, list):
        return [
            _issue(
                "ATOMIC_REVIEW_INVALID",
                "An atomic partial review omitted its canonical diagnostics.",
            )
        ]
    return [issue for issue in raw_issues if isinstance(issue, Mapping)]


def _count_value(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _base_atomic_counts(rule_graph: Mapping[str, object]) -> dict[str, int]:
    rule_counts = rule_graph.get("rule_counts")
    safe_rule_counts = rule_counts if isinstance(rule_counts, Mapping) else {}
    atom_rows = rule_graph.get("atoms")
    materialities: Counter[str] = Counter()
    if isinstance(atom_rows, list):
        materialities.update(
            str(materiality)
            for row in atom_rows
            if isinstance(row, Mapping)
            and isinstance((materiality := row.get("materiality")), str)
        )
    return {
        "atom_claims": 0,
        "atoms": _count_value(safe_rule_counts.get("atoms")),
        "critical_atoms": materialities[AtomMateriality.CRITICAL.value],
        "material_atoms": materialities[AtomMateriality.MATERIAL.value],
        "not_applicable_elements": 0,
        "not_established_elements": 0,
        "relationship_claims": 0,
        "relationships": _count_value(safe_rule_counts.get("relationships")),
        "stated_elements": 0,
        "supporting_atoms": materialities[AtomMateriality.SUPPORTING.value],
        "visible_atoms": 0,
        "visible_relationships": 0,
    }


def _project_atomic_lead_reviews(
    dispositions: Sequence[DraftLeadDispositionV2],
) -> list[DraftLeadReview] | None:
    """Project v2 lead dispositions for unchanged legacy recall semantics."""
    projected: dict[str, dict[str, object]] = {}
    for disposition in dispositions:
        try:
            validated = DraftLeadDispositionV2.model_validate(
                disposition.model_dump(mode="python", warnings=False)
            )
        except (AttributeError, TypeError, ValueError):
            return None
        state = projected.setdefault(
            validated.lead_id,
            {"gap_codes": set(), "not_material_rationales": set()},
        )
        if validated.disposition is LeadDispositionV2.GAP:
            gap_codes = state["gap_codes"]
            if not isinstance(gap_codes, set):
                return None
            gap_codes.update(validated.gap_codes)
        elif validated.disposition is LeadDispositionV2.NOT_MATERIAL:
            rationales = state["not_material_rationales"]
            if not isinstance(rationales, set) or validated.rationale is None:
                return None
            rationales.add(validated.rationale)

    reviews: list[DraftLeadReview] = []
    for lead_id, state in sorted(projected.items()):
        gap_codes = state["gap_codes"]
        rationales = state["not_material_rationales"]
        if not isinstance(gap_codes, set) or not isinstance(rationales, set):
            return None
        if gap_codes:
            reviews.append(
                DraftLeadReview(
                    lead_id=lead_id,
                    disposition=LeadReviewDisposition.GAP,
                    gap_codes=sorted(str(code) for code in gap_codes),
                    rationale=(
                        "Projected from atomic lead dispositions with gap precedence."
                    ),
                )
            )
        elif rationales:
            reviews.append(
                DraftLeadReview(
                    lead_id=lead_id,
                    disposition=LeadReviewDisposition.NOT_MATERIAL,
                    rationale=sorted(str(value) for value in rationales)[0],
                )
            )
    return reviews


def _validated_atomic_rows(
    draft: AnalysisDraft,
) -> tuple[dict[str, DraftRuleAtom], dict[str, DraftRuleRelationship]] | None:
    try:
        atoms = {
            atom.atom_id: DraftRuleAtom.model_validate(
                atom.model_dump(mode="python", warnings=False)
            )
            for atom in draft.rule_atoms
        }
        relationships = {
            relationship.relationship_id: DraftRuleRelationship.model_validate(
                relationship.model_dump(mode="python", warnings=False)
            )
            for relationship in draft.rule_relationships
        }
    except (AttributeError, TypeError, ValueError):
        return None
    if len(atoms) != len(draft.rule_atoms) or len(relationships) != len(
        draft.rule_relationships
    ):
        return None
    return atoms, relationships


def _atom_targets(
    atom: DraftRuleAtom,
    targets: TargetIndexes,
) -> tuple[Target, ...]:
    return tuple(
        target
        for target_id in (*atom.unit_ids, *atom.lead_ids)
        if (
            target := targets.unit_by_id.get(target_id)
            or targets.lead_by_id.get(target_id)
        )
        is not None
    )


def _validate_atom_evidence(
    atoms: Mapping[str, DraftRuleAtom],
    targets: TargetIndexes,
    claims: Mapping[str, ClaimRecord],
    gaps: Mapping[str, GapRecord],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> set[str]:
    invalid_atom_ids: set[str] = set()
    for atom_id, atom in sorted(atoms.items()):
        assigned_targets = _atom_targets(atom, targets)
        assigned_sources = {target.source_id for target in assigned_targets}
        covered_targets: set[str] = set()
        for element_name in DraftRuleAtomElements.model_fields:
            element = getattr(atom.elements, element_name)
            if element.status is CoverageElementStatus.STATED:
                element_has_exact_evidence = False
                for claim_id in element.claim_ids:
                    claim = claims.get(claim_id)
                    if claim is None:
                        invalid_atom_ids.add(atom_id)
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_CLAIM_UNKNOWN",
                            "A stated atom element references an unknown built claim.",
                            atom_id,
                            claim_id,
                        )
                        continue
                    if claim.kind is not ClaimKind.SOURCE_SUPPORTED:
                        invalid_atom_ids.add(atom_id)
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_CLAIM_NOT_SOURCE_SUPPORTED",
                            (
                                "A stated atom element references a claim that is "
                                "not source-supported."
                            ),
                            atom_id,
                            claim_id,
                        )
                        continue
                    if not claim.spans:
                        invalid_atom_ids.add(atom_id)
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                            "A stated atom claim has no resolved exact source evidence.",
                            atom_id,
                            element_name,
                            claim_id,
                        )
                        continue
                    overlapping = {
                        target.target_id
                        for target in assigned_targets
                        if any(
                            span_overlaps_target(span, target)
                            for span in claim.spans
                        )
                    }
                    if not overlapping:
                        invalid_atom_ids.add(atom_id)
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                            "Exact stated-element evidence does not overlap an assigned target.",
                            atom_id,
                            element_name,
                            claim_id,
                        )
                        continue
                    element_has_exact_evidence = True
                    covered_targets.update(overlapping)
                if not element_has_exact_evidence:
                    invalid_atom_ids.add(atom_id)
            elif element.status is CoverageElementStatus.NOT_ESTABLISHED:
                covered_gap_sources: set[str] = set()
                for gap_code in element.gap_codes:
                    gap = gaps.get(gap_code)
                    if (
                        gap is None
                        or gap.category != atom.category.value
                        or not gap.source_ids
                        or len(gap.source_ids) != len(set(gap.source_ids))
                        or not set(gap.source_ids).issubset(assigned_sources)
                    ):
                        invalid_atom_ids.add(atom_id)
                        _append_issue(
                            issues,
                            issue_keys,
                            "ATOMIC_GAP_INVALID",
                            "A not-established atom element requires a valid source-tied gap.",
                            atom_id,
                            element_name,
                            gap_code,
                        )
                        continue
                    covered_gap_sources.update(gap.source_ids)
                for source_id in sorted(assigned_sources - covered_gap_sources):
                    invalid_atom_ids.add(atom_id)
                    _append_issue(
                        issues,
                        issue_keys,
                        "ATOMIC_GAP_INVALID",
                        "A not-established atom element lacks a gap for an assigned source.",
                        atom_id,
                        element_name,
                        source_id,
                    )
        for target in assigned_targets:
            if target.target_id in covered_targets:
                continue
            invalid_atom_ids.add(atom_id)
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
                "Exact atom evidence does not cover an assigned target.",
                atom_id,
                target.target_id,
            )
    return invalid_atom_ids


def _validate_relationship_evidence(
    relationships: Mapping[str, DraftRuleRelationship],
    atoms: Mapping[str, DraftRuleAtom],
    targets: TargetIndexes,
    claims: Mapping[str, ClaimRecord],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> set[str]:
    invalid_relationship_ids: set[str] = set()
    for relationship_id, relationship in sorted(relationships.items()):
        source_targets = _atom_targets(atoms[relationship.source_atom_id], targets)
        target_targets = _atom_targets(atoms[relationship.target_atom_id], targets)
        for claim_id in relationship.claim_ids:
            claim = claims.get(claim_id)
            valid = (
                claim is not None
                and claim.kind is ClaimKind.SOURCE_SUPPORTED
                and bool(claim.spans)
                and any(
                    span_overlaps_target(span, target)
                    for span in claim.spans
                    for target in source_targets
                )
                and any(
                    span_overlaps_target(span, target)
                    for span in claim.spans
                    for target in target_targets
                )
            )
            if valid:
                continue
            invalid_relationship_ids.add(relationship_id)
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
                (
                    "A relationship claim requires exact source-supported evidence "
                    "from both endpoint contexts."
                ),
                relationship_id,
                claim_id,
            )
    return invalid_relationship_ids


def _validated_brief(brief: object) -> tuple[AttorneyBrief | None, bool]:
    if brief is None:
        return None, True
    try:
        if not isinstance(brief, AttorneyBrief):
            raise TypeError("brief is not typed")
        return (
            AttorneyBrief.model_validate(
                brief.model_dump(mode="python", warnings=False)
            ),
            True,
        )
    except (AttributeError, TypeError, ValueError):
        return None, False


def _bindings_by_location(
    values: Mapping[str, tuple[str, ...]],
) -> dict[str, set[str]]:
    by_location: dict[str, set[str]] = {}
    for identifier, locations in values.items():
        for location in locations:
            by_location.setdefault(location, set()).add(identifier)
    return by_location


def _visibility_requirements(
    atoms: Mapping[str, DraftRuleAtom],
    relationships: Mapping[str, DraftRuleRelationship],
    draft: AnalysisDraft,
    bindings: BriefBindingIndex,
) -> tuple[set[str], set[str]]:
    base_atoms = {
        atom_id
        for atom_id, atom in atoms.items()
        if atom.materiality in {AtomMateriality.CRITICAL, AtomMateriality.MATERIAL}
    }
    for unit_review in draft.unit_reviews:
        for dimension_name in _DIMENSION_NAMES:
            dimension = getattr(unit_review.dimensions, dimension_name)
            if dimension.disposition is UnitDimensionDisposition.MAPPED:
                base_atoms.update(dimension.atom_ids)

    required_relationships = set(bindings.relationship_locations).intersection(
        relationships
    )
    required_relationships.update(
        relationship_id
        for relationship_id, relationship in relationships.items()
        if {
            relationship.source_atom_id,
            relationship.target_atom_id,
        }.intersection(base_atoms)
    )
    required_atoms = set(base_atoms)
    for relationship_id in required_relationships:
        relationship = relationships[relationship_id]
        required_atoms.update(
            (relationship.source_atom_id, relationship.target_atom_id)
        )
    return required_atoms, required_relationships


def _validate_visibility(
    atoms: Mapping[str, DraftRuleAtom],
    relationships: Mapping[str, DraftRuleRelationship],
    draft: AnalysisDraft,
    bindings: BriefBindingIndex,
    invalid_evidence_atoms: set[str],
    invalid_evidence_relationships: set[str],
    *,
    issues: list[dict[str, object]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    for atom_id in sorted(set(bindings.atom_locations) - set(atoms)):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_BRIEF_BINDING_INVALID",
            "Visible legal analysis references an unknown rule atom.",
            atom_id,
        )
    for relationship_id in sorted(
        set(bindings.relationship_locations) - set(relationships)
    ):
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_BRIEF_BINDING_INVALID",
            "Visible legal analysis references an unknown rule relationship.",
            relationship_id,
        )

    claims_by_location = _bindings_by_location(bindings.claim_locations)
    atoms_by_location = _bindings_by_location(bindings.atom_locations)
    required_atoms, required_relationships = _visibility_requirements(
        atoms, relationships, draft, bindings
    )
    visible_atoms = set(bindings.atom_locations).intersection(atoms)
    for atom_id in sorted(required_atoms | visible_atoms):
        locations = bindings.atom_locations.get(atom_id, ())
        if not locations:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_ATOM_NOT_VISIBLE",
                "A visibility-required rule atom is absent from legal analysis.",
                atom_id,
            )
            continue
        if atom_id in invalid_evidence_atoms:
            continue
        required_claims = set(atoms[atom_id].claim_ids)
        if not any(
            required_claims.issubset(claims_by_location.get(location, set()))
            for location in locations
        ):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_ATOM_CLAIM_NOT_VISIBLE",
                "A visible rule atom lacks co-bound claims for all stated elements.",
                atom_id,
            )

    for relationship_id in sorted(required_relationships):
        if relationship_id in invalid_evidence_relationships:
            continue
        relationship = relationships[relationship_id]
        if not any(
            relationship.source_atom_id
            in atoms_by_location.get(location, set())
            and relationship.target_atom_id
            in atoms_by_location.get(location, set())
            and bool(
                set(relationship.claim_ids).intersection(
                    claims_by_location.get(location, set())
                )
            )
            for location in bindings.relationship_locations.get(
                relationship_id, ()
            )
        ):
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_RELATIONSHIP_NOT_VISIBLE",
                (
                    "A material relationship must co-bind both endpoints and an "
                    "evidence claim in one legal-analysis unit."
                ),
                relationship_id,
                relationship.source_atom_id,
                relationship.target_atom_id,
            )


def _complete_atomic_counts(
    counts: dict[str, int],
    atoms: Mapping[str, DraftRuleAtom],
    relationships: Mapping[str, DraftRuleRelationship],
    bindings: BriefBindingIndex,
) -> dict[str, int]:
    statuses: Counter[str] = Counter()
    for atom in atoms.values():
        statuses.update(
            getattr(atom.elements, element_name).status.value
            for element_name in DraftRuleAtomElements.model_fields
        )
    counts.update(
        {
            "atom_claims": len(
                {
                    claim_id
                    for atom in atoms.values()
                    for claim_id in atom.claim_ids
                }
            ),
            "not_applicable_elements": statuses[
                CoverageElementStatus.NOT_APPLICABLE.value
            ],
            "not_established_elements": statuses[
                CoverageElementStatus.NOT_ESTABLISHED.value
            ],
            "relationship_claims": len(
                {
                    claim_id
                    for relationship in relationships.values()
                    for claim_id in relationship.claim_ids
                }
            ),
            "stated_elements": statuses[CoverageElementStatus.STATED.value],
            "visible_atoms": len(set(bindings.atom_locations).intersection(atoms)),
            "visible_relationships": len(
                set(bindings.relationship_locations).intersection(relationships)
            ),
        }
    )
    return counts


def evaluate_atomic_coverage(
    source_unit_inventory: Mapping[str, object],
    evidence_inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, object]:
    """Compose exact v2 target, graph, evidence, visibility, and recall closure."""
    target_review = evaluate_atomic_target_review(
        source_unit_inventory, evidence_inventory, draft, sources
    )
    rule_graph = evaluate_rule_graph(draft)
    counts = _base_atomic_counts(rule_graph)
    partial_issues = [
        *_partial_review_issues(target_review),
        *_partial_review_issues(rule_graph),
    ]
    if target_review.get("valid") is not True or rule_graph.get("valid") is not True:
        return compose_atomic_coverage_review(
            target_review=target_review,
            rule_graph=rule_graph,
            counts=counts,
            issues=partial_issues,
        )

    validated_rows = _validated_atomic_rows(draft)
    if validated_rows is None:
        return compose_atomic_coverage_review(
            target_review=target_review,
            rule_graph=rule_graph,
            counts=counts,
            issues=[
                _issue(
                    "ATOMIC_EVIDENCE_INVALID",
                    "The validated atomic graph could not be snapshotted safely.",
                )
            ],
        )
    atoms, relationships = validated_rows

    try:
        targets, target_index_issues = target_indexes(
            source_unit_inventory, evidence_inventory, sources
        )
        claims, claim_issues = claim_index(draft, sources)
        gaps, gap_issues = gap_index(draft)
    except (AttributeError, KeyError, TypeError, ValueError):
        return compose_atomic_coverage_review(
            target_review=target_review,
            rule_graph=rule_graph,
            counts=counts,
            issues=[
                _issue(
                    "ATOMIC_EVIDENCE_INVALID",
                    "Atomic evidence indexes could not be built safely.",
                )
            ],
        )
    index_issues: list[dict[str, object]] = []
    index_issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    for incoming, code in (
        (target_index_issues, "ATOMIC_EVIDENCE_INVALID"),
        (claim_issues, "ATOMIC_EVIDENCE_INVALID"),
        (gap_issues, "ATOMIC_GAP_INVALID"),
    ):
        _extend_index_issues(
            index_issues,
            index_issue_keys,
            incoming,
            code=code,
        )
    if index_issues:
        return compose_atomic_coverage_review(
            target_review=target_review,
            rule_graph=rule_graph,
            counts=counts,
            issues=index_issues,
        )

    issues: list[dict[str, object]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    invalid_atoms = _validate_atom_evidence(
        atoms,
        targets,
        claims,
        gaps,
        issues=issues,
        issue_keys=issue_keys,
    )
    invalid_relationships = _validate_relationship_evidence(
        relationships,
        atoms,
        targets,
        claims,
        issues=issues,
        issue_keys=issue_keys,
    )

    safe_brief, brief_valid = _validated_brief(draft.brief)
    bindings = brief_binding_index(safe_brief)
    if not brief_valid:
        _append_issue(
            issues,
            issue_keys,
            "ATOMIC_BRIEF_INVALID",
            "The authored brief is malformed and cannot establish atomic visibility.",
        )
    else:
        _validate_visibility(
            atoms,
            relationships,
            draft,
            bindings,
            invalid_atoms,
            invalid_relationships,
            issues=issues,
            issue_keys=issue_keys,
        )

    evidence_issue_codes = {
        "ATOMIC_CLAIM_UNKNOWN",
        "ATOMIC_CLAIM_NOT_SOURCE_SUPPORTED",
        "ATOMIC_EVIDENCE_OUTSIDE_TARGET",
        "ATOMIC_GAP_INVALID",
        "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID",
    }
    if not any(issue["code"] in evidence_issue_codes for issue in issues):
        projected_reviews = _project_atomic_lead_reviews(draft.lead_dispositions_v2)
        if projected_reviews is None:
            _append_issue(
                issues,
                issue_keys,
                "ATOMIC_LEAD_RECALL_INVALID",
                "Atomic lead dispositions could not be projected safely.",
            )
        else:
            try:
                recall = evaluate_provision_recall(
                    evidence_inventory,
                    draft.model_copy(update={"lead_reviews": projected_reviews}),
                    sources,
                )
            except (AttributeError, KeyError, TypeError, ValueError):
                recall = {"valid": False, "unresolved_lead_ids": []}
            if recall.get("valid") is not True:
                unresolved_ids = recall.get("unresolved_lead_ids")
                _append_issue(
                    issues,
                    issue_keys,
                    "ATOMIC_LEAD_RECALL_INVALID",
                    "Atomic lead dispositions do not satisfy unchanged provision recall.",
                    *(
                        unresolved_ids
                        if isinstance(unresolved_ids, list)
                        else []
                    ),
                )

    _complete_atomic_counts(counts, atoms, relationships, bindings)
    return compose_atomic_coverage_review(
        target_review=target_review,
        rule_graph=rule_graph,
        counts=counts,
        issues=issues,
    )
