import importlib.util
import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from regulatory_harvest.analysis.report import render_audit_markdown, render_markdown
from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    BriefItem,
    BriefSection,
    BriefSectionRole,
    BriefStructureProfile,
    BriefSubsection,
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    Gap,
    IssueCategory,
    PresentationRole,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceInput,
    SourceQuality,
    SourceRecord,
    SourceRole,
    ValidationReport,
)
from regulatory_harvest.validation import validate_bundle

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "regulatory_harvest_portable_report_parity",
    ROOT / "scripts" / "harvest_portable.py",
)
assert SPEC is not None and SPEC.loader is not None
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


def _terminal_bundle(
    *, include_optional_roles: bool, include_adaptive_brief: bool
) -> ResearchBundle:
    now = datetime(2026, 8, 10, 18, 0, tzinfo=UTC)
    text = "A controller must document material risks."
    source = SourceRecord(
        source_id="src_rule",
        origin="captures/rule.txt",
        canonical_url="https://example.org/rule?view=official#section-4",
        display_name="Example Rule",
        retrieved_at=now,
        content_hash="a" * 64,
        media_type="text/plain",
        normalized_text=text,
        title="Example Rule",
        publisher="Example Legislature",
        jurisdiction="US",
        authority_type="enacted regulation",
        citation="Example Rule section 4",
        effective_date="2026-01-01",
        supersession="No later amendment identified as of 2026-08-10.",
        language="en",
        source_quality=SourceQuality.PRIMARY,
        source_role=(
            SourceRole.OFFICIAL_PRIMARY if include_optional_roles else None
        ),
    )
    citation = CitationSpan(
        citation_id="cite_rule",
        source_id=source.source_id,
        start_char=0,
        end_char=len(text),
        quote=text,
    )
    issue = ResearchIssue(
        issue_id="issue-requirements",
        title="Operative requirements",
        description="What covered controllers must do.",
        jurisdictions=["US"],
        category=IssueCategory.REQUIREMENTS,
        presentation_role=(
            PresentationRole.REQUIREMENT if include_optional_roles else None
        ),
    )
    finding = Finding(
        finding_id="finding-documentation",
        issue_id=issue.issue_id,
        title="Controllers must document material risks",
        jurisdiction="US",
        authority="Example Rule section 4",
        severity=Severity.HIGH,
        practical_implication="Create a risk record before deployment.",
        claims=[
            Claim(
                claim_id="claim-documentation",
                text=text,
                kind=ClaimKind.SOURCE_SUPPORTED,
                citation_ids=[citation.citation_id],
            )
        ],
    )
    brief = (
        AttorneyBrief(
            executive_summary=[
                BriefBlock(
                    kind=BriefBlockKind.PARAGRAPH,
                    purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                    text="The rule requires a documented material-risk assessment.",
                    finding_ids=[finding.finding_id],
                )
            ],
            sections=[
                BriefSection(
                    section_id="operational-obligations",
                    title="Operational Obligations",
                    blocks=[
                        BriefBlock(
                            kind=BriefBlockKind.BULLET_LIST,
                            purpose=BriefBlockPurpose.APPLICATION,
                            items=[
                                BriefItem(
                                    text="Create the risk record before deployment.",
                                    finding_ids=[finding.finding_id],
                                )
                            ],
                        )
                    ],
                )
            ],
        )
        if include_adaptive_brief
        else None
    )
    return ResearchBundle(
        generator_version="0.1.0",
        request=ResearchRequest(
            request_id="parity",
            question="What does the example rule require?",
            matter_title="Example Regulation" if include_optional_roles else None,
            jurisdictions=["US"],
            as_of=date(2026, 8, 10),
            source_inputs=[
                SourceInput(
                    location="captures/rule.txt",
                    source_role=(
                        SourceRole.OFFICIAL_PRIMARY if include_optional_roles else None
                    ),
                )
            ],
        ),
        manifest=RunManifest(
            run_id="parity",
            generator_version="0.1.0",
            created_at=now,
            updated_at=now,
            provider_metadata={
                "model_provider": "test-host",
                "model": "test-model",
            },
        ),
        sources=[source],
        issues=[issue],
        findings=[finding],
        citations=[citation],
        gaps=[
            Gap(
                gap_id="gap-client-facts",
                code="FACTUAL_CONTEXT_REQUIRED",
                message="Client facts were not supplied.",
                category=IssueCategory.IMPLEMENTATION,
                presentation_role=(
                    PresentationRole.CLIENT_FACTS if include_optional_roles else None
                ),
                jurisdiction="US",
                source_ids=[source.source_id],
            )
        ],
        brief=brief,
        validation=ValidationReport(valid=True, validated_at=now),
    )


def _profiled_terminal_bundle() -> ResearchBundle:
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    finding_id = bundle.findings[0].finding_id
    claim_id = bundle.findings[0].claims[0].claim_id
    claim_text = bundle.findings[0].claims[0].text
    bundle.gaps.append(
        Gap(
            gap_id="gap-enforcement",
            code="ENFORCEMENT_NOT_ESTABLISHED",
            message="The authority does not establish penalties or enforcement mechanisms.",
            category=IssueCategory.ENFORCEMENT,
            jurisdiction="US",
        )
    )
    bundle.brief = AttorneyBrief(
        structure_profile=BriefStructureProfile.REGULATORY_WALK_V1,
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text=claim_text,
                finding_ids=[finding_id],
                claim_ids=[claim_id],
            )
        ],
        sections=[
            BriefSection(
                section_id="key-requirements",
                title="Key Requirements",
                role=BriefSectionRole.KEY_REQUIREMENTS,
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.BULLET_LIST,
                        purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                        items=[
                            BriefItem(
                                text=claim_text,
                                finding_ids=[finding_id],
                                claim_ids=[claim_id],
                            )
                        ],
                    )
                ],
            ),
            BriefSection(
                section_id="penalties-and-enforcement",
                title="Penalties and Enforcement",
                role=BriefSectionRole.PENALTIES_ENFORCEMENT,
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.LIMITATION,
                        text=(
                            "Not established: The authority does not establish penalties "
                            "or enforcement mechanisms."
                        ),
                    )
                ],
            ),
            BriefSection(
                section_id="implementation-workplan",
                title="Implementation Workplan",
                role=BriefSectionRole.IMPLEMENTATION,
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Create a risk record before deployment.",
                        finding_ids=[finding_id],
                    )
                ],
            ),
        ],
    )
    return bundle


_STRUCTURAL_CODES = {
    "BRIEF_MATTER_TITLE_MISSING",
    "BRIEF_CANONICAL_SECTION_MISSING",
    "BRIEF_CANONICAL_SECTION_DUPLICATE",
    "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
    "BRIEF_CANONICAL_SECTION_ORDER_INVALID",
    "BRIEF_SECTION_ROLE_MISSING",
    "BRIEF_REQUIREMENT_FINDING_MISPLACED",
    "BRIEF_ENFORCEMENT_FINDING_MISPLACED",
    "BRIEF_NOT_ESTABLISHED_MISSING",
    "BRIEF_NOT_ESTABLISHED_GAP_MISSING",
    "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
    "BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
}


def _structural_issues(bundle: ResearchBundle) -> list[dict[str, object]]:
    return [
        issue.model_dump(mode="json")
        for issue in validate_bundle(bundle).issues
        if issue.code in _STRUCTURAL_CODES
    ]


def _apply_structural_failure(bundle: ResearchBundle, scenario: str) -> None:
    assert bundle.brief is not None
    brief = bundle.brief
    if scenario == "missing":
        brief.sections.pop()
    elif scenario == "duplicate":
        brief.sections.append(
            brief.sections[-1].model_copy(
                update={"section_id": "implementation-workplan-two"}
            )
        )
    elif scenario == "role-missing":
        brief.sections[-1].role = None
    elif scenario == "title":
        brief.sections[0].title = "Operative Duties"
    elif scenario == "reserved-title":
        brief.sections.append(
            BriefSection(
                section_id="other-requirements",
                title="Key Requirements",
                role=BriefSectionRole.OTHER,
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Confirm the operational owner.",
                    )
                ],
            )
        )
    elif scenario == "order":
        brief.sections[0], brief.sections[1] = brief.sections[1], brief.sections[0]
    elif scenario == "requirement-placement":
        brief.sections[0].blocks[0].items[0].finding_ids = []
    elif scenario == "not-established":
        brief.sections[1].blocks[0].text = "Enforcement remains unresolved."
    elif scenario == "gap":
        bundle.gaps = [
            gap for gap in bundle.gaps if gap.category is not IssueCategory.ENFORCEMENT
        ]
    elif scenario == "enforcement-placement":
        enforcement_issue = bundle.issues[0].model_copy(
            update={"issue_id": "issue-enforcement", "category": IssueCategory.ENFORCEMENT}
        )
        enforcement_finding = bundle.findings[0].model_copy(
            update={
                "finding_id": "finding-enforcement",
                "issue_id": enforcement_issue.issue_id,
                "claims": [
                    bundle.findings[0].claims[0].model_copy(
                        update={"claim_id": "claim-enforcement"}
                    )
                ],
            }
        )
        bundle.issues.append(enforcement_issue)
        bundle.findings.append(enforcement_finding)
        bundle.gaps = [
            gap for gap in bundle.gaps if gap.category is not IssueCategory.ENFORCEMENT
        ]
        brief.executive_summary.append(
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="The rule provides an enforcement consequence.",
                finding_ids=[enforcement_finding.finding_id],
            )
        )
    elif scenario == "matter-title":
        bundle.request.matter_title = None
    elif scenario == "blank-matter-title":
        bundle.request.matter_title = "   "
    elif scenario == "requirements-purpose":
        brief.sections[0].blocks[0].purpose = BriefBlockPurpose.APPLICATION
    elif scenario == "requirements-purpose-nested":
        brief.sections[0].subsections.append(
            BriefSubsection(
                subsection_id="operational-sequence",
                title="Operational Sequence",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Assign the compliance owner.",
                    )
                ],
            )
        )
    elif scenario == "implementation-purpose":
        brief.sections[2].blocks[0].purpose = BriefBlockPurpose.LEGAL_ANALYSIS
    else:
        raise AssertionError(f"Unknown structural scenario: {scenario}")


@pytest.mark.parametrize(
    "scenario",
    [
        "missing",
        "duplicate",
        "role-missing",
        "title",
        "reserved-title",
        "order",
        "requirement-placement",
        "enforcement-placement",
        "not-established",
        "gap",
        "matter-title",
        "blank-matter-title",
        "requirements-purpose",
        "requirements-purpose-nested",
        "implementation-purpose",
    ],
)
def test_portable_and_full_structural_validation_match(scenario: str) -> None:
    """Every structural failure must be identical in both packaged runtimes."""
    bundle = _profiled_terminal_bundle()
    _apply_structural_failure(bundle, scenario)

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"] in _STRUCTURAL_CODES
    ]

    assert portable_issues == _structural_issues(bundle)


def test_portable_and_full_validation_ignore_structure_for_older_brief() -> None:
    """Unprofiled terminal bundles must retain the prior adaptive contract."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"] in _STRUCTURAL_CODES
    ]

    assert portable_issues == _structural_issues(bundle) == []


def test_portable_and_full_validation_match_claim_bound_profiled_briefs() -> None:
    """Both runtimes must reject invented prose despite a valid finding identifier."""
    binding_codes = {
        "BRIEF_LEGAL_ANALYSIS_CLAIM_MISSING",
        "BRIEF_CLAIM_MISSING",
        "BRIEF_CLAIM_EVIDENCE_INVALID",
        "BRIEF_CLAIM_FINDING_MISMATCH",
        "BRIEF_LEGAL_ANALYSIS_TEXT_UNSUPPORTED",
    }
    valid_bundle = _profiled_terminal_bundle()
    invalid_bundle = _profiled_terminal_bundle()
    assert invalid_bundle.brief is not None
    invalid_bundle.brief.executive_summary[0].text = (
        "A controller must transfer one billion dollars to every regulator."
    )

    results: list[list[dict[str, object]]] = []
    for bundle in (valid_bundle, invalid_bundle):
        full = [
            issue.model_dump(mode="json")
            for issue in validate_bundle(bundle).issues
            if issue.code in binding_codes
        ]
        packaged = [
            issue
            for issue in portable._validate_bundle(json.loads(bundle.model_dump_json()))
            if issue["code"] in binding_codes
        ]
        assert packaged == full
        results.append(full)

    assert results[0] == []
    assert results[1][0]["code"] == "BRIEF_LEGAL_ANALYSIS_TEXT_UNSUPPORTED"


def test_portable_and_full_validation_require_typed_enforcement_claim_roles() -> None:
    """Both runtimes must reject generic claim IDs and accept an explicit dual role."""
    bundle = _profiled_terminal_bundle()
    source_claim = bundle.findings[0].claims[0]
    enforcement_issue = ResearchIssue(
        issue_id="issue-enforcement",
        title="Penalty",
        jurisdictions=["US"],
        category=IssueCategory.ENFORCEMENT,
    )
    enforcement_claim = Claim.model_validate(
        {
            **source_claim.model_dump(mode="json"),
            "claim_id": "claim-enforcement",
            "text": "A violation permits the agency to impose a civil penalty.",
        }
    )
    bundle.issues.append(enforcement_issue)
    bundle.findings.append(
        Finding(
            finding_id="finding-enforcement",
            issue_id=enforcement_issue.issue_id,
            title="Civil penalty",
            jurisdiction="US",
            authority="Example Rule section 4",
            severity=Severity.HIGH,
            practical_implication="Review the supported penalty.",
            claims=[enforcement_claim],
        )
    )
    bundle.gaps = [gap for gap in bundle.gaps if gap.category is not IssueCategory.ENFORCEMENT]
    assert bundle.brief is not None
    penalty = bundle.brief.sections[1]
    penalty.blocks = [
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            text=enforcement_claim.text,
            finding_ids=["finding-enforcement"],
            claim_ids=["claim-enforcement"],
            enforcement_trigger_claim_ids=["claim-enforcement"],
            enforcement_consequence_claim_ids=["claim-enforcement"],
        )
    ]

    def role_issues() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        full = [
            issue.model_dump(mode="json")
            for issue in validate_bundle(bundle).issues
            if issue.code == "BRIEF_ENFORCEMENT_ROLE_INVALID"
        ]
        packaged = [
            issue
            for issue in portable._validate_bundle(json.loads(bundle.model_dump_json()))
            if issue["code"] == "BRIEF_ENFORCEMENT_ROLE_INVALID"
        ]
        return full, packaged

    full, packaged = role_issues()
    assert packaged == full
    assert [issue["code"] for issue in full] == ["BRIEF_ENFORCEMENT_ROLE_INVALID"]

    bundle.findings[-1].claims[0] = Claim.model_validate(
        {
            **bundle.findings[-1].claims[0].model_dump(mode="json"),
            "enforcement_roles": ["trigger", "consequence"],
        }
    )
    assert role_issues() == ([], [])


def test_portable_and_full_renderers_match_for_structured_bundle() -> None:
    """Drift between packaged runtimes would give attorneys different reports."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)

    portable_bundle = json.loads(bundle.model_dump_json())
    assert portable._render_report(portable_bundle) == render_markdown(bundle)
    assert portable._render_audit(portable_bundle) == render_audit_markdown(bundle)


def test_portable_and_full_renderers_match_for_older_bundle_defaults() -> None:
    """Adding optional roles must not fork the report produced from older bundles."""
    bundle = _terminal_bundle(include_optional_roles=False, include_adaptive_brief=False)

    portable_bundle = json.loads(bundle.model_dump_json())
    assert portable._render_report(portable_bundle) == render_markdown(bundle)
    assert portable._render_audit(portable_bundle) == render_audit_markdown(bundle)


def _narrative_issues(bundle: ResearchBundle) -> list[dict[str, object]]:
    return [
        issue.model_dump(mode="json")
        for issue in validate_bundle(bundle).issues
        if issue.code
        in {
            "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL",
            "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS",
        }
    ]


def test_portable_and_full_validation_match_for_source_framed_legal_analysis() -> None:
    """The dependency-free installation must enforce the same direct-voice rule."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    assert bundle.brief is not None
    bundle.brief.executive_summary[0].text = (
        "The retained materials establish the documentation duty."
    )

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"] == "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS"
    ]

    assert portable_issues == _narrative_issues(bundle)


@pytest.mark.parametrize(
    "text",
    [
        "The materials collected by a covered entity must be destroyed within 30 days.",
        "The official summary must accompany the application.",
    ],
)
def test_portable_and_full_validation_allow_direct_rules_with_source_like_nouns(
    text: str,
) -> None:
    """Source-like nouns must not trigger the narration guard without a reporting verb."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    assert bundle.brief is not None
    bundle.brief.executive_summary[0].text = text

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"] == "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS"
    ]

    assert portable_issues == _narrative_issues(bundle) == []


def test_portable_and_full_validation_match_for_nonlegal_summary_lead() -> None:
    """Both runtimes must keep an evidence caveat from displacing the legal answer."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    assert bundle.brief is not None
    bundle.brief.executive_summary.insert(
        0,
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LIMITATION,
            text="The retained materials do not establish currentness.",
        ),
    )

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"] == "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL"
    ]

    assert portable_issues == _narrative_issues(bundle)


def test_portable_and_full_validation_allow_explicit_source_limitation() -> None:
    """Narrative validation must preserve candid source-sufficiency limitations."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    assert bundle.brief is not None
    bundle.brief.executive_summary.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LIMITATION,
            text="The retained materials do not establish currentness.",
        )
    )

    portable_bundle = json.loads(bundle.model_dump_json())
    portable_issues = [
        issue
        for issue in portable._validate_bundle(portable_bundle)
        if issue["code"]
        in {
            "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL",
            "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS",
        }
    ]

    assert portable_issues == _narrative_issues(bundle) == []


def test_portable_and_full_currentness_wording_is_explicit_and_identical() -> None:
    """Both runtime paths must explain an unverified currentness boundary the same way."""
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)

    full_line = next(
        line for line in render_markdown(bundle).splitlines() if line.startswith("**Currentness:**")
    )
    portable_line = next(
        line
        for line in portable._render_report(json.loads(bundle.model_dump_json())).splitlines()
        if line.startswith("**Currentness:**")
    )

    assert full_line == portable_line
    assert "Not independently verified through 2026-08-10" in full_line
    assert "retained cited primary authority: Example Rule section 4" in full_line
    assert "latest retained authority" not in full_line
    assert "attorney verification required" in full_line


def test_portable_and_full_currentness_omit_uncited_primary_sources() -> None:
    bundle = _terminal_bundle(include_optional_roles=True, include_adaptive_brief=True)
    bundle.findings[0].claims = []
    bundle.citations = []

    full_line = next(
        line for line in render_markdown(bundle).splitlines() if line.startswith("**Currentness:**")
    )
    portable_line = next(
        line
        for line in portable._render_report(json.loads(bundle.model_dump_json())).splitlines()
        if line.startswith("**Currentness:**")
    )

    assert full_line == portable_line
    assert "Example Rule section 4" not in full_line
    assert "retained cited primary authority: not identified" in full_line
