import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftClaim,
    DraftFinding,
    DraftGap,
    DraftIssue,
    DraftLeadReview,
    ProposedCitation,
    build_evidence_inventory,
    evaluate_provision_recall,
)
from regulatory_harvest.models import ClaimKind, Severity, SourceRecord
from regulatory_harvest.storage import sha256_digest

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "regulatory_harvest_portable_coverage",
    ROOT / "scripts" / "harvest_portable.py",
)
assert SPEC is not None and SPEC.loader is not None
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)

TEXT = "A violation is subject to a civil penalty of $10,000."


def _source() -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Synthetic Rule",
        retrieved_at=datetime(2026, 8, 11, tzinfo=UTC),
        content_hash=sha256_digest(TEXT.encode()),
        media_type="text/plain",
        normalized_text=TEXT,
        jurisdiction="US",
    )


def _inventory() -> dict[str, object]:
    return build_evidence_inventory([_source().model_dump(mode="json")])


def _draft(
    *,
    include_finding: bool,
    gaps: list[DraftGap] | None = None,
    lead_reviews: list[DraftLeadReview] | None = None,
) -> AnalysisDraft:
    issues = [
        DraftIssue(
            issue_id="issue-enforcement",
            title="Penalties",
            category="enforcement",
            jurisdictions=["US"],
        )
    ]
    findings = (
        [
            DraftFinding(
                finding_id="finding-penalty",
                issue_id="issue-enforcement",
                title="Civil penalty",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Evaluate exposure for each violation.",
                claims=[
                    DraftClaim(
                        claim_id="claim-penalty",
                        text=TEXT,
                        kind=ClaimKind.SOURCE_SUPPORTED,
                        proposed_citations=[
                            ProposedCitation(source_id="src_rule", quote=TEXT)
                        ],
                    )
                ],
            )
        ]
        if include_finding
        else []
    )
    return AnalysisDraft(
        issues=issues,
        findings=findings,
        gaps=gaps or [],
        lead_reviews=lead_reviews or [],
    )


def _lead_id() -> str:
    leads = _inventory()["leads"]
    assert isinstance(leads, list) and len(leads) == 1
    return leads[0]["lead_id"]


def test_exact_category_matched_citation_resolves_a_provision_lead() -> None:
    review = evaluate_provision_recall(
        _inventory(),
        _draft(include_finding=True),
        [_source()],
    )

    assert review["valid"] is True
    assert review["unresolved_lead_ids"] == []
    assert review["resolved_counts"] == {"finding": 1}
    assert review["leads"][0]["status"] == "finding"
    assert review["leads"][0]["related_ids"] == ["finding-penalty", "claim-penalty"]


def test_one_cited_duty_does_not_resolve_neighboring_duties_in_same_provision() -> None:
    first_duty = "A controller must maintain a written register."
    text = (
        "Section 4 - Duties\n"
        f"{first_duty} "
        "The controller must notify affected persons. "
        "The controller must preserve supporting records."
    )
    source = SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Synthetic Rule",
        retrieved_at=datetime(2026, 8, 11, tzinfo=UTC),
        content_hash=sha256_digest(text.encode()),
        media_type="text/plain",
        normalized_text=text,
        jurisdiction="US",
    )
    draft = AnalysisDraft(
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Duties",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-register",
                issue_id="issue-requirements",
                title="Written register",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Maintain the required register.",
                claims=[
                    DraftClaim(
                        claim_id="claim-register",
                        text=first_duty,
                        kind=ClaimKind.SOURCE_SUPPORTED,
                        proposed_citations=[
                            ProposedCitation(source_id="src_rule", quote=first_duty)
                        ],
                    )
                ],
            )
        ],
    )
    inventory = build_evidence_inventory([source.model_dump(mode="json")])

    review = evaluate_provision_recall(inventory, draft, [source])
    duty_leads = [
        lead for lead in inventory["leads"] if lead["topic"] == "duties"
    ]
    unresolved_duties = {
        lead["lead_id"]
        for lead in duty_leads
        if lead["lead_id"] in review["unresolved_lead_ids"]
    }

    assert len(duty_leads) == 3
    assert len(unresolved_duties) == 2
    assert review["valid"] is False


def test_generic_category_gap_does_not_silently_resolve_responsive_text() -> None:
    gap = DraftGap(
        code="ENFORCEMENT_NOT_ESTABLISHED",
        message="Enforcement was not established.",
        category="enforcement",
        source_ids=["src_rule"],
    )

    review = evaluate_provision_recall(
        _inventory(),
        _draft(include_finding=False, gaps=[gap]),
        [_source()],
    )

    assert review["valid"] is False
    assert review["unresolved_lead_ids"] == [_lead_id()]
    assert {issue["code"] for issue in review["issues"]} == {
        "PROVISION_LEAD_UNRESOLVED"
    }


def test_legacy_draft_without_coverage_contract_still_requires_lead_review() -> None:
    draft = _draft(include_finding=False)

    review = evaluate_provision_recall(_inventory(), draft, [_source()])

    assert draft.coverage_contract_version is None
    assert draft.lead_reviews == []
    assert review["valid"] is False
    assert review["unresolved_lead_ids"] == [_lead_id()]
    assert {issue["code"] for issue in review["issues"]} == {
        "PROVISION_LEAD_UNRESOLVED"
    }


def test_explicit_gap_review_must_match_category_source_and_code() -> None:
    gap = DraftGap(
        code="PENALTY_AMOUNT_INCOMPLETE",
        message="The excerpt does not establish how the amount is calculated.",
        category="enforcement",
        source_ids=["src_rule"],
    )
    valid_draft = _draft(
        include_finding=False,
        gaps=[gap],
        lead_reviews=[
            DraftLeadReview(
                lead_id=_lead_id(),
                disposition="gap",
                gap_codes=[gap.code],
                rationale="The signal identifies a penalty but leaves the calculation open.",
            )
        ],
    )

    valid = evaluate_provision_recall(_inventory(), valid_draft, [_source()])
    invalid = evaluate_provision_recall(
        _inventory(),
        valid_draft.model_copy(
            update={
                "lead_reviews": [
                    DraftLeadReview(
                        lead_id=_lead_id(),
                        disposition="gap",
                        gap_codes=["UNKNOWN_GAP"],
                        rationale="The cited gap does not exist.",
                    )
                ]
            }
        ),
        [_source()],
    )

    assert valid["valid"] is True
    assert valid["resolved_counts"] == {"gap": 1}
    assert invalid["valid"] is False
    assert {issue["code"] for issue in invalid["issues"]} == {
        "PROVISION_LEAD_GAP_INVALID"
    }


def test_not_material_review_is_explicit_and_portable_contract_matches() -> None:
    draft = _draft(
        include_finding=False,
        lead_reviews=[
            DraftLeadReview(
                lead_id=_lead_id(),
                disposition="not_material",
                rationale=(
                    "The sentence is a cross-reference example and does not create the "
                    "penalty at issue."
                ),
            )
        ],
    )

    full = evaluate_provision_recall(_inventory(), draft, [_source()])
    portable_result = portable._evaluate_provision_recall(
        _inventory(),
        draft.model_dump(mode="json"),
        [_source().model_dump(mode="json")],
    )

    assert full["valid"] is True
    assert full["resolved_counts"] == {"not_material": 1}
    assert portable_result == full


def test_nonpriority_research_lead_informs_analysis_without_blocking_delivery() -> None:
    inventory = _inventory()
    leads = inventory["leads"]
    assert isinstance(leads, list)
    leads[0]["review_required"] = False
    inventory["priority_lead_count"] = 0
    inventory["priority_topic_counts"] = {}

    full = evaluate_provision_recall(
        inventory,
        _draft(include_finding=False),
        [_source()],
    )
    portable_result = portable._evaluate_provision_recall(
        inventory,
        _draft(include_finding=False).model_dump(mode="json"),
        [_source().model_dump(mode="json")],
    )

    assert full["valid"] is True
    assert full["priority_lead_count"] == 0
    assert full["resolved_counts"] == {"informational": 1}
    assert full["unresolved_lead_ids"] == []
    assert portable_result == full


def test_lead_review_model_rejects_ambiguous_dispositions_and_duplicates() -> None:
    with pytest.raises(ValidationError, match="gap_codes"):
        DraftLeadReview(
            lead_id="lead_one",
            disposition="gap",
            rationale="A gap disposition must name the matching gap.",
        )
    with pytest.raises(ValidationError, match="gap_codes"):
        DraftLeadReview(
            lead_id="lead_one",
            disposition="not_material",
            gap_codes=["SHOULD_NOT_BE_HERE"],
            rationale="A nonmaterial disposition cannot delegate to a gap.",
        )
    review = DraftLeadReview(
        lead_id="lead_one",
        disposition="not_material",
        rationale="The signal is outside the scoped legal question.",
    )
    with pytest.raises(ValidationError, match="unique"):
        AnalysisDraft(issues=[], findings=[], lead_reviews=[review, review])
