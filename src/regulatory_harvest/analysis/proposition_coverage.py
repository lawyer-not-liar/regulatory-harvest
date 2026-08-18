"""Deterministic reconciliation of proposition coverage against prepared targets."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from regulatory_harvest.models import (
    ClaimKind,
    CoverageDisposition,
    CoverageElementStatus,
    IssueCategory,
    LeadReviewDisposition,
    PropositionType,
    SourceRecord,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .atomic_coverage import (
    ATOMIC_COVERAGE_CONTRACT_VERSION,
    evaluate_atomic_coverage,
)
from .coverage import evaluate_provision_recall
from .coverage_common import (
    _ClaimRecord,
    _Target,
    brief_binding_index,
    claim_index,
    gap_index,
    span_overlaps_target,
    target_indexes,
)
from .drafts import (
    AnalysisDraft,
    DraftCoverageElements,
    DraftLeadReview,
    DraftPropositionCoverage,
)
from .inventory import PROVISION_LEADS_VERSION
from .source_units import SOURCE_UNIT_INVENTORY_VERSION

COVERAGE_CONTRACT_VERSION = "proposition-coverage-v1"

_ELEMENT_NAMES = (
    "subject",
    "operative_rule",
    "object",
    "trigger_or_threshold",
    "conditions_or_exceptions",
    "timing",
    "consequence_or_remedy",
    "authority_or_route",
)
_ISSUE_CATEGORIES = frozenset(category.value for category in IssueCategory)
_PROPOSITION_TYPES = frozenset(item.value for item in PropositionType)


def _coverage_issue(code: str, message: str, *related_ids: str) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "related_ids": sorted(set(related_ids)),
    }


def _append_issue(
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
    issues.append(_coverage_issue(code, message, *safe_ids))


def _extend_index_issues(
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
    incoming: Sequence[Mapping[str, object]],
) -> None:
    for issue in incoming:
        code = issue.get("code")
        message = issue.get("message")
        related_ids = issue.get("related_ids")
        if not isinstance(code, str) or not isinstance(message, str):
            continue
        _append_issue(
            issues,
            issue_keys,
            code,
            message,
            *(related_ids if isinstance(related_ids, list) else []),
        )


def _row_key(row: DraftPropositionCoverage) -> tuple[str, bytes]:
    return row.coverage_id, canonical_json_bytes(
        row.model_dump(mode="json", warnings=False)
    )


def _row_target_sources(
    row: DraftPropositionCoverage,
    unit_by_id: Mapping[str, _Target],
    lead_by_id: Mapping[str, _Target],
) -> set[str]:
    return {
        target.source_id
        for target_id in (*row.unit_ids, *row.lead_ids)
        if (
            target := unit_by_id.get(target_id) or lead_by_id.get(target_id)
        )
        is not None
    }


def _not_established_elements(
    elements: DraftCoverageElements | None,
) -> list[str]:
    if elements is None:
        return []
    return [
        name
        for name in _ELEMENT_NAMES
        if getattr(elements, name).status is CoverageElementStatus.NOT_ESTABLISHED
    ]


def _validate_row_structure(
    row: DraftPropositionCoverage,
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> None:
    coverage_id = row.coverage_id
    proposition_type = getattr(row.proposition_type, "value", row.proposition_type)
    disposition = getattr(row.disposition, "value", row.disposition)
    identifier_fields = {
        "unit_ids": row.unit_ids,
        "lead_ids": row.lead_ids,
        "claim_ids": row.claim_ids,
        "gap_codes": row.gap_codes,
    }
    for field_name, values in identifier_fields.items():
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)
            or len(values) != len(set(values))
        ):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                f"Coverage row {field_name} must contain unique nonblank identifiers.",
                coverage_id,
            )
    if not row.unit_ids and not row.lead_ids:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Coverage row must reference at least one prepared target.",
            coverage_id,
        )
    if not isinstance(proposition_type, str) or proposition_type not in _PROPOSITION_TYPES:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Coverage row proposition type is not controlled.",
            coverage_id,
        )

    if disposition == CoverageDisposition.COVERED.value:
        if not row.claim_ids:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Covered row must reference at least one claim.",
                coverage_id,
            )
        not_established = _not_established_elements(row.elements)
        if bool(not_established) != bool(row.gap_codes):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Covered row gap codes must correspond to not-established elements.",
                coverage_id,
            )
        return

    if disposition == CoverageDisposition.GAP.value:
        if row.claim_ids or not row.gap_codes or not row.rationale:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Gap row requires gaps and rationale and cannot reference claims.",
                coverage_id,
            )
        if row.elements is not None and any(
            getattr(row.elements, name).status is CoverageElementStatus.STATED
            for name in _ELEMENT_NAMES
        ):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Gap row cannot contain stated elements.",
                coverage_id,
            )
        return

    if disposition == CoverageDisposition.NOT_MATERIAL.value and (
        row.elements is not None or row.claim_ids or row.gap_codes or not row.rationale
    ):
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "Not-material row requires only targets and a concrete rationale.",
            coverage_id,
        )


def _validated_coverage_rows(
    value: object,
    *,
    issues: list[dict[str, Any]],
    issue_keys: set[tuple[str, str, tuple[str, ...]]],
) -> list[DraftPropositionCoverage]:
    if not isinstance(value, list):
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The proposition coverage ledger is malformed.",
        )
        return []

    rows: list[DraftPropositionCoverage] = []
    for row in value:
        if not isinstance(row, DraftPropositionCoverage):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "The proposition coverage ledger contains a malformed row.",
            )
            continue
        related_ids: tuple[str, ...] = ()
        try:
            payload = row.model_dump(mode="python", warnings=False)
            raw_coverage_id = payload.get("coverage_id")
            if isinstance(raw_coverage_id, str) and raw_coverage_id.strip():
                related_ids = (raw_coverage_id,)
            rows.append(DraftPropositionCoverage.model_validate(payload))
        except (AttributeError, TypeError, ValueError):
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "The proposition coverage ledger contains a malformed row.",
                *related_ids,
            )
    return rows


def evaluate_proposition_coverage(
    source_unit_inventory: Mapping[str, object],
    evidence_inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, Any]:
    """Reconcile every prepared unit and lead to a valid proposition disposition."""
    issues: list[dict[str, Any]] = []
    issue_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    if draft.coverage_contract_version != COVERAGE_CONTRACT_VERSION:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The draft coverage contract is missing or mismatched.",
        )
    if source_unit_inventory.get("inventory_version") != SOURCE_UNIT_INVENTORY_VERSION:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The prepared source-unit inventory version is missing or mismatched.",
        )
    if evidence_inventory.get("inventory_version") != PROVISION_LEADS_VERSION:
        _append_issue(
            issues,
            issue_keys,
            "COVERAGE_ROW_INVALID",
            "The prepared provision-lead inventory version is missing or mismatched.",
        )

    targets, target_issues = target_indexes(
        source_unit_inventory, evidence_inventory, sources
    )
    _extend_index_issues(issues, issue_keys, target_issues)
    unit_objects = targets.unit_objects
    lead_objects = targets.lead_objects
    units = targets.units
    leads = targets.leads
    declared_unit_ids = targets.declared_unit_ids
    declared_lead_ids = targets.declared_lead_ids
    unit_by_id = targets.unit_by_id
    lead_by_id = targets.lead_by_id

    claims, claim_issues = claim_index(draft, sources)
    _extend_index_issues(issues, issue_keys, claim_issues)
    build_available = not any(
        issue.get("message")
        == "The analysis draft could not be reconciled into exact evidence."
        for issue in claim_issues
    )
    claim_locations = brief_binding_index(draft.brief).claim_locations

    gap_by_code, gap_issues = gap_index(draft)
    _extend_index_issues(issues, issue_keys, gap_issues)

    rows = _validated_coverage_rows(
        draft.proposition_coverage,
        issues=issues,
        issue_keys=issue_keys,
    )

    row_id_counts = Counter(row.coverage_id for row in rows)
    for coverage_id, count in sorted(row_id_counts.items()):
        if count > 1:
            _append_issue(
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

    for row in sorted(rows, key=_row_key):
        coverage_id = row.coverage_id
        _validate_row_structure(row, issues=issues, issue_keys=issue_keys)
        category = (
            row.category.value
            if isinstance(row.category, IssueCategory)
            else str(row.category)
        )
        disposition = (
            row.disposition.value
            if isinstance(row.disposition, CoverageDisposition)
            else str(row.disposition)
        )
        proposition_type = getattr(row.proposition_type, "value", row.proposition_type)
        proposition_type_value = str(proposition_type)
        disposition_counts[disposition] += 1

        for unit_id in row.unit_ids:
            if unit_id in declared_unit_ids:
                coverage_by_unit[unit_id].add(coverage_id)
            else:
                _append_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_TARGET_UNKNOWN",
                    "Coverage row references a unit outside the prepared inventory.",
                    coverage_id,
                    unit_id,
                )
        for lead_id in row.lead_ids:
            if lead_id in declared_lead_ids:
                coverage_by_lead[lead_id].add(coverage_id)
            else:
                _append_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_TARGET_UNKNOWN",
                    "Coverage row references a lead outside the prepared inventory.",
                    coverage_id,
                    lead_id,
                )

        if category not in _ISSUE_CATEGORIES:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Coverage row category is not a controlled issue category.",
                coverage_id,
            )
        if disposition not in {item.value for item in CoverageDisposition}:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_ROW_INVALID",
                "Coverage row disposition is not controlled.",
                coverage_id,
            )

        if disposition in {
            CoverageDisposition.COVERED.value,
            CoverageDisposition.GAP.value,
        }:
            for lead_id in row.lead_ids:
                target = lead_by_id.get(lead_id)
                if target is not None and target.category != category:
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_ROW_INVALID",
                        "Coverage row category is incompatible with a referenced lead.",
                        coverage_id,
                        lead_id,
                    )

        target_sources = _row_target_sources(row, unit_by_id, lead_by_id)
        valid_gap_codes: set[str] = set()
        for gap_code in row.gap_codes:
            gap = gap_by_code.get(gap_code)
            if (
                gap is None
                or gap.category != category
                or len(gap.source_ids) != len(set(gap.source_ids))
                or set(gap.source_ids) != target_sources
            ):
                _append_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_GAP_INVALID",
                    "Coverage gap must be unique, authored, category-matched, and target-bound.",
                    coverage_id,
                    gap_code,
                )
                continue
            valid_gap_codes.add(gap_code)

        not_established = _not_established_elements(row.elements)
        if disposition == CoverageDisposition.COVERED.value:
            if row.elements is None:
                _append_issue(
                    issues,
                    issue_keys,
                    "COVERAGE_ELEMENT_INCOMPLETE",
                    "Covered row is missing the complete element map.",
                    coverage_id,
                )
            else:
                for element_name in ("subject", "operative_rule"):
                    if (
                        getattr(row.elements, element_name).status
                        is not CoverageElementStatus.STATED
                    ):
                        _append_issue(
                            issues,
                            issue_keys,
                            "COVERAGE_ELEMENT_INCOMPLETE",
                            "Covered row is missing a required stated element.",
                            coverage_id,
                            element_name,
                        )
            if not valid_gap_codes:
                for element_name in not_established:
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_ELEMENT_INCOMPLETE",
                        "A not-established element lacks a valid authored row gap.",
                        coverage_id,
                        element_name,
                    )

        eligible_claims: list[_ClaimRecord] = []
        if disposition == CoverageDisposition.COVERED.value and build_available:
            for claim_id in row.claim_ids:
                claim = claims.get(claim_id)
                if claim is None:
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_UNKNOWN",
                        "Covered row references a claim outside the built analysis.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if claim.kind is not ClaimKind.SOURCE_SUPPORTED:
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_NOT_SOURCE_SUPPORTED",
                        "Covered row references a claim that is not source-supported.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if claim.category != category:
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_ROW_INVALID",
                        "Covered claim category does not match the coverage row.",
                        coverage_id,
                        claim_id,
                    )
                    continue
                if not claim_locations.get(claim_id):
                    _append_issue(
                        issues,
                        issue_keys,
                        "COVERAGE_CLAIM_NOT_VISIBLE",
                        "Covered claim is absent from visible legal analysis.",
                        coverage_id,
                        claim_id,
                    )
                if not claim.spans:
                    _append_issue(
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
                    span for claim in eligible_claims for span in claim.spans
                ]
                for target_id in row.unit_ids:
                    target = unit_by_id.get(target_id)
                    if target is not None and not any(
                        span_overlaps_target(span, target) for span in exact_spans
                    ):
                        _append_issue(
                            issues,
                            issue_keys,
                            "COVERAGE_EVIDENCE_OUTSIDE_TARGET",
                            "Exact claim evidence does not overlap a referenced unit.",
                            coverage_id,
                            target_id,
                        )
                for target_id in row.lead_ids:
                    target = lead_by_id.get(target_id)
                    if target is not None and not any(
                        span_overlaps_target(span, target) for span in exact_spans
                    ):
                        _append_issue(
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
                for claim_id in row.claim_ids
                for path in claim_locations.get(claim_id, [])
            }
        )
        row_results.append(
            {
                "coverage_id": coverage_id,
                "category": category,
                "proposition_type": proposition_type_value,
                "disposition": disposition,
                "unit_ids": sorted(row.unit_ids),
                "lead_ids": sorted(row.lead_ids),
                "claim_ids": sorted(row.claim_ids),
                "gap_codes": sorted(row.gap_codes),
                "brief_locations": brief_locations,
                "rationale": row.rationale,
                "valid": not any(
                    coverage_id in issue["related_ids"] for issue in issues
                ),
            }
        )

    for target in units:
        if not coverage_by_unit[target.target_id]:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_TARGET_UNRESOLVED",
                "Required source unit has no proposition coverage disposition.",
                target.target_id,
            )
    for target in leads:
        if not coverage_by_lead[target.target_id]:
            _append_issue(
                issues,
                issue_keys,
                "COVERAGE_TARGET_UNRESOLVED",
                "Provision lead has no proposition coverage disposition.",
                target.target_id,
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
            "unit_id": target.target_id,
            "source_id": target.source_id,
            "status": "mapped" if coverage_by_unit[target.target_id] else "unresolved",
            "coverage_ids": sorted(coverage_by_unit[target.target_id]),
        }
        for target in sorted(
            units,
            key=lambda target: (
                target.source_id,
                target.start_char,
                target.end_char,
                target.target_id,
            ),
        )
    ]
    lead_results = [
        {
            "lead_id": target.target_id,
            "source_id": target.source_id,
            "issue_category": target.category,
            "status": "mapped" if coverage_by_lead[target.target_id] else "unresolved",
            "coverage_ids": sorted(coverage_by_lead[target.target_id]),
        }
        for target in sorted(
            leads,
            key=lambda target: (
                target.source_id,
                target.start_char,
                target.end_char,
                target.target_id,
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


def evaluate_coverage_closure(
    evidence_inventory: Mapping[str, object],
    source_unit_inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, Any]:
    """Dispatch exact v1 proposition or v2 atomic coverage closure."""
    if draft.coverage_contract_version == ATOMIC_COVERAGE_CONTRACT_VERSION:
        return evaluate_atomic_coverage(
            source_unit_inventory,
            evidence_inventory,
            draft,
            sources,
        )
    proposition = evaluate_proposition_coverage(
        source_unit_inventory, evidence_inventory, draft, sources
    )
    recall_draft = draft
    if draft.coverage_contract_version == COVERAGE_CONTRACT_VERSION:
        projected_reviews = _project_strict_lead_reviews(proposition)
        recall_draft = draft.model_copy(
            update={"lead_reviews": projected_reviews or []}
        )
    lead_recall = evaluate_provision_recall(
        evidence_inventory, recall_draft, sources
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "coverage_contract_version": COVERAGE_CONTRACT_VERSION,
        "valid": lead_recall["valid"] is True and proposition["valid"] is True,
        "lead_recall": lead_recall,
        "proposition_coverage": proposition,
    }
    payload["coverage_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload


def _project_strict_lead_reviews(
    proposition: Mapping[str, object],
) -> list[DraftLeadReview] | None:
    """Project valid strict gap/not-material rows into the legacy recall input."""
    if proposition.get("valid") is not True:
        return None
    rows = proposition.get("rows")
    if not isinstance(rows, list):
        return None
    projected: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or row.get("valid") is not True:
            return None
        disposition = row.get("disposition")
        if disposition not in {
            CoverageDisposition.GAP.value,
            CoverageDisposition.NOT_MATERIAL.value,
        }:
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
            or (disposition == CoverageDisposition.GAP.value and not gap_codes)
            or (disposition == CoverageDisposition.NOT_MATERIAL.value and gap_codes)
        ):
            return None
        for lead_id in lead_ids:
            state = projected.setdefault(
                lead_id,
                {"gap_codes": set(), "gap_rows": set(), "not_material_rows": set()},
            )
            if disposition == CoverageDisposition.GAP.value:
                state["gap_codes"].update(gap_codes)
                state["gap_rows"].add(coverage_id)
            else:
                state["not_material_rows"].add(coverage_id)
    reviews: list[DraftLeadReview] = []
    for lead_id, state in sorted(projected.items()):
        gap_rows = sorted(state["gap_rows"])
        not_material_rows = sorted(state["not_material_rows"])
        if gap_rows:
            disposition = LeadReviewDisposition.GAP
            gap_codes = sorted(state["gap_codes"])
            coverage_ids = gap_rows
        else:
            disposition = LeadReviewDisposition.NOT_MATERIAL
            gap_codes = []
            coverage_ids = not_material_rows
        reviews.append(
            DraftLeadReview(
                lead_id=lead_id,
                disposition=disposition,
                gap_codes=gap_codes,
                rationale=(
                    "Projected from strict proposition coverage rows: "
                    + ", ".join(coverage_ids)
                    + "."
                ),
            )
        )
    return reviews
