"""Deterministic recall review for provision leads."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from regulatory_harvest.models import LeadReviewDisposition, SourceRecord
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .build import build_analysis
from .drafts import AnalysisDraft


def _issue(code: str, lead_id: str, message: str, *related_ids: str) -> dict[str, Any]:
    return {
        "code": code,
        "lead_id": lead_id,
        "message": message,
        "related_ids": list(related_ids),
    }


def _lead_objects(inventory: Mapping[str, object]) -> list[dict[str, Any]]:
    raw_leads = inventory.get("leads", [])
    if not isinstance(raw_leads, list):
        return []
    return [dict(lead) for lead in raw_leads if isinstance(lead, dict)]


def evaluate_provision_recall(
    inventory: Mapping[str, object],
    draft: AnalysisDraft,
    sources: Sequence[SourceRecord],
) -> dict[str, Any]:
    """Resolve provision leads through exact evidence or an explicit disposition."""
    leads = _lead_objects(inventory)
    lead_by_id = {
        lead["lead_id"]: lead
        for lead in leads
        if isinstance(lead.get("lead_id"), str) and lead["lead_id"]
    }
    reviews = {review.lead_id: review for review in draft.lead_reviews}
    issues: list[dict[str, Any]] = []
    for submitted_review in draft.lead_reviews:
        if submitted_review.lead_id not in lead_by_id:
            issues.append(
                _issue(
                    "PROVISION_LEAD_UNKNOWN",
                    submitted_review.lead_id,
                    "Lead review references an identifier outside the prepared inventory.",
                )
            )

    built = build_analysis(draft, list(sources))
    category_by_issue = {issue.issue_id: issue.category.value for issue in built.issues}
    citation_by_id = {citation.citation_id: citation for citation in built.citations}
    exact_spans: list[dict[str, Any]] = []
    for finding in built.findings:
        category = category_by_issue.get(finding.issue_id)
        if category is None:
            continue
        for claim in finding.claims:
            for citation_id in claim.citation_ids:
                citation = citation_by_id.get(citation_id)
                if citation is None:
                    continue
                exact_spans.append(
                    {
                        "source_id": citation.source_id,
                        "category": category,
                        "start_char": citation.start_char,
                        "end_char": citation.end_char,
                        "finding_id": finding.finding_id,
                        "claim_id": claim.claim_id,
                    }
                )

    draft_gaps = list(draft.gaps)
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
                _issue(
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
        if review is not None and review.disposition is LeadReviewDisposition.NOT_MATERIAL:
            lead_results.append(
                {
                    "lead_id": lead_id,
                    "status": "not_material",
                    "related_ids": [],
                    "rationale": review.rationale,
                }
            )
            continue
        if review is not None and review.disposition is LeadReviewDisposition.GAP:
            matching_codes = {
                gap.code
                for gap in draft_gaps
                if gap.code in review.gap_codes
                and gap.category.value == category
                and source_id in gap.source_ids
            }
            if matching_codes == set(review.gap_codes):
                lead_results.append(
                    {
                        "lead_id": lead_id,
                        "status": "gap",
                        "related_ids": sorted(matching_codes),
                        "rationale": review.rationale,
                    }
                )
                continue
            issues.append(
                _issue(
                    "PROVISION_LEAD_GAP_INVALID",
                    lead_id,
                    "Gap review must name an authored gap with the lead category and source.",
                    *review.gap_codes,
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
                _issue(
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
                "rationale": review.rationale if review is not None else None,
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
    payload["coverage_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload
