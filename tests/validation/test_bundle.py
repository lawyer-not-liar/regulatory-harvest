import hashlib
import json
from datetime import UTC, date, datetime

import pytest

from regulatory_harvest.evaluation.attorney_artifacts import _derive_deterministic_checks
from regulatory_harvest.evaluation.attorney_models import CandidateReport, CandidateRole
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
    BriefTableRow,
    CitationSpan,
    Claim,
    ClaimKind,
    FetchStatus,
    Finding,
    Gap,
    IssueCategory,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceFailure,
    SourceInput,
    SourceQuality,
    SourceRecord,
)
from regulatory_harvest.storage import (
    calculate_bundle_hash,
    migrate_bundle_hash_contract,
    sha256_digest,
)
from regulatory_harvest.validation import validate_bundle

NOW = datetime(2026, 8, 5, tzinfo=UTC)
TEXT = "A controller must document material deployment risks."


def _source() -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Example Rule",
        retrieved_at=NOW,
        content_hash=sha256_digest(TEXT.encode()),
        media_type="text/plain",
        normalized_text=TEXT,
        jurisdiction="US",
        source_quality=SourceQuality.PRIMARY,
    )


def _bundle() -> ResearchBundle:
    source = _source()
    quote = "must document material deployment risks"
    start = TEXT.index(quote)
    citation = CitationSpan(
        citation_id="cite-1",
        source_id=source.source_id,
        start_char=start,
        end_char=start + len(quote),
        quote=quote,
    )
    claim = Claim(
        claim_id="claim-1",
        text="A controller must document material deployment risks.",
        kind=ClaimKind.SOURCE_SUPPORTED,
        citation_ids=[citation.citation_id],
    )
    finding = Finding(
        finding_id="finding-1",
        issue_id="issue-1",
        title="Risk documentation",
        jurisdiction="US",
        authority="Example Rule",
        severity=Severity.MEDIUM,
        practical_implication="Maintain risk documentation.",
        claims=[claim],
    )
    request = ResearchRequest(
        request_id="demo",
        question="What applies?",
        matter_title="Example Regulation",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="rule.txt")],
    )
    return ResearchBundle(
        generator_version="0.1.0",
        request=request,
        manifest=RunManifest(
            run_id="demo",
            generator_version="0.1.0",
            created_at=NOW,
            updated_at=NOW,
        ),
        sources=[source],
        issues=[
            ResearchIssue(
                issue_id="issue-1",
                title="Risk documentation",
                jurisdictions=["US"],
                category=IssueCategory.REQUIREMENTS,
            )
        ],
        findings=[finding],
        citations=[citation],
        gaps=[
            Gap(
                gap_id=f"gap-{category.value}",
                code=f"COVERAGE_{category.value.upper()}_NOT_ESTABLISHED",
                message=f"The retained source set did not establish {category.value}.",
                category=category,
            )
            for category in (
                IssueCategory.STATUS,
                IssueCategory.SCOPE,
                IssueCategory.ENFORCEMENT,
                IssueCategory.DEADLINES,
                IssueCategory.IMPLEMENTATION,
            )
        ],
    )


def _codes(bundle: ResearchBundle) -> set[str]:
    return {issue.code for issue in validate_bundle(bundle).issues}


def _historical_schema_10_payload(
    bundle: ResearchBundle,
    *,
    initial_release_shape: bool = False,
) -> dict[str, object]:
    """Build the exact field projection shipped by the original schema-1.0 model."""
    payload = bundle.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("brief", None)
    payload.pop("bundle_hash", None)
    request = payload["request"]
    assert isinstance(request, dict)
    request.pop("matter_title", None)
    if initial_release_shape:
        request.pop("source_mode", None)
    for source_input in request["source_inputs"]:
        keys = ["canonical_url", "language", "source_role"]
        if initial_release_shape:
            keys.extend(("publisher", "effective_date", "supersession"))
        for key in keys:
            source_input.pop(key, None)
    for source in payload["sources"]:
        for key in ("canonical_url", "language", "source_role"):
            source.pop(key, None)
    for issue in payload["issues"]:
        issue.pop("category", None)
        issue.pop("presentation_role", None)
    for finding in payload["findings"]:
        for claim in finding["claims"]:
            claim.pop("enforcement_roles", None)
    for gap in payload["gaps"]:
        gap.pop("category", None)
        gap.pop("presentation_role", None)
    return payload


def _historical_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _brief() -> AttorneyBrief:
    return AttorneyBrief(
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="A controller must document material deployment risks.",
                finding_ids=["finding-1"],
                claim_ids=["claim-1"],
            )
        ],
        sections=[
            BriefSection(
                section_id="risk-documentation",
                title="Risk Documentation",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.BULLET_LIST,
                        purpose=BriefBlockPurpose.APPLICATION,
                        items=[
                            BriefItem(
                                text="Maintain the record.",
                                finding_ids=["finding-1"],
                            )
                        ],
                    )
                ],
            )
        ],
    )


def _profiled_brief() -> AttorneyBrief:
    return AttorneyBrief(
        structure_profile=BriefStructureProfile.REGULATORY_WALK_V1,
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="A controller must document material deployment risks.",
                finding_ids=["finding-1"],
                claim_ids=["claim-1"],
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
                                text="A controller must document material deployment risks.",
                                finding_ids=["finding-1"],
                                claim_ids=["claim-1"],
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
                            "Not established: The retained evidence does not establish "
                            "penalties or enforcement mechanisms."
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
                        kind=BriefBlockKind.NUMBERED_LIST,
                        purpose=BriefBlockPurpose.APPLICATION,
                        items=[BriefItem(text="Confirm the facts needed for implementation.")],
                    )
                ],
            ),
        ],
    )


def _issues_for(bundle: ResearchBundle, code: str) -> list[dict[str, object]]:
    return [
        issue.model_dump(mode="json")
        for issue in validate_bundle(bundle).issues
        if issue.code == code
    ]


def test_valid_bundle_passes_deterministic_validation() -> None:
    """A correct evidence graph must remain a usable export."""
    report = validate_bundle(_bundle())
    assert report.valid is True
    assert not {issue.code for issue in report.issues if issue.level == "error"}


def test_valid_adaptive_brief_passes_reference_and_coverage_validation() -> None:
    """A complete brief must not be rejected merely for using adaptive headings."""
    bundle = _bundle()
    bundle.brief = _brief()

    report = validate_bundle(bundle)

    assert report.valid is True
    assert not {issue.code for issue in report.issues if issue.code.startswith("BRIEF_")}


def test_valid_regulatory_walk_profile_passes_structural_validation() -> None:
    """The canonical legal walk must pass without weakening adaptive content."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()

    report = validate_bundle(bundle)

    assert report.valid is True
    assert not {issue.code for issue in report.issues if issue.code.startswith("BRIEF_")}


@pytest.mark.parametrize("matter_title", [None, "   "])
def test_profiled_brief_requires_a_concrete_matter_title(
    matter_title: str | None,
) -> None:
    """A profiled attorney brief must identify the authority in its heading."""
    bundle = _bundle()
    bundle.request.matter_title = matter_title
    bundle.brief = _profiled_brief()

    assert _issues_for(bundle, "BRIEF_MATTER_TITLE_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_MATTER_TITLE_MISSING",
            "path": "request.matter_title",
            "message": "A profiled attorney brief requires a concrete matter title.",
            "related_ids": ["regulatory-walk-v1"],
        }
    ]


def test_unprofiled_bundle_retains_the_legacy_title_fallback() -> None:
    """Older bundles without the new profile must remain valid and renderable."""
    bundle = _bundle()
    bundle.request.matter_title = None
    bundle.brief = _brief()

    assert "BRIEF_MATTER_TITLE_MISSING" not in _codes(bundle)


@pytest.mark.parametrize(
    "purpose",
    [BriefBlockPurpose.APPLICATION, BriefBlockPurpose.CLIENT_FACT],
)
def test_key_requirements_rejects_nonlegal_block_purposes(
    purpose: BriefBlockPurpose,
) -> None:
    """Operational advice must not be presented as a legal requirement."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[0].blocks.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=purpose,
            text="Create the compliance workstream.",
        )
    )

    assert _issues_for(bundle, "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
            "path": "brief.sections[0].blocks[1].purpose",
            "message": (
                "Key Requirements may contain only legal-analysis or limitation blocks."
            ),
            "related_ids": ["key_requirements"],
        }
    ]


def test_key_requirements_rejects_nonlegal_purpose_in_a_subsection() -> None:
    """Nesting must not bypass the requirements-purpose boundary."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[0].subsections.append(
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

    assert _issues_for(bundle, "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
            "path": "brief.sections[0].subsections[0].blocks[0].purpose",
            "message": (
                "Key Requirements may contain only legal-analysis or limitation blocks."
            ),
            "related_ids": ["key_requirements"],
        }
    ]


def test_implementation_workplan_rejects_legal_analysis_blocks() -> None:
    """The workplan must not become a duplicate statement of the law."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[2].blocks.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            text="The rule requires documentation.",
            finding_ids=["finding-1"],
        )
    )

    assert _issues_for(bundle, "BRIEF_IMPLEMENTATION_PURPOSE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
            "path": "brief.sections[2].blocks[1].purpose",
            "message": (
                "Implementation Workplan may contain only application, client-fact, "
                "or limitation blocks."
            ),
            "related_ids": ["implementation"],
        }
    ]


def test_profiled_brief_requires_each_canonical_section() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections.pop()

    assert _issues_for(bundle, "BRIEF_CANONICAL_SECTION_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_CANONICAL_SECTION_MISSING",
            "path": "brief.sections",
            "message": "Profiled attorney brief is missing a required canonical section.",
            "related_ids": ["implementation"],
        }
    ]


def test_profiled_brief_rejects_duplicate_canonical_role() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    duplicate = bundle.brief.sections[-1].model_copy(
        update={"section_id": "implementation-workplan-two"}
    )
    bundle.brief.sections.append(duplicate)

    assert _issues_for(bundle, "BRIEF_CANONICAL_SECTION_DUPLICATE") == [
        {
            "level": "error",
            "code": "BRIEF_CANONICAL_SECTION_DUPLICATE",
            "path": "brief.sections",
            "message": "Profiled attorney brief contains a canonical section role more than once.",
            "related_ids": ["implementation"],
        }
    ]


def test_profiled_brief_requires_a_role_on_every_section() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[-1].role = None

    assert _issues_for(bundle, "BRIEF_SECTION_ROLE_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_SECTION_ROLE_MISSING",
            "path": "brief.sections[2].role",
            "message": "Every section in a profiled attorney brief must declare a semantic role.",
            "related_ids": ["implementation-workplan"],
        }
    ]


def test_profiled_brief_requires_canonical_section_titles() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[0].title = "Operative Duties"

    assert _issues_for(bundle, "BRIEF_CANONICAL_SECTION_TITLE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
            "path": "brief.sections[0].title",
            "message": "Canonical section role must use its required heading.",
            "related_ids": ["key_requirements"],
        }
    ]


def test_profiled_brief_prevents_other_section_from_reusing_canonical_heading() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections.append(
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

    assert _issues_for(bundle, "BRIEF_CANONICAL_SECTION_TITLE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
            "path": "brief.sections[3].title",
            "message": "Canonical heading may be used only by its matching section role.",
            "related_ids": ["key_requirements"],
        }
    ]


def test_profiled_brief_requires_canonical_section_order() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[0], bundle.brief.sections[1] = (
        bundle.brief.sections[1],
        bundle.brief.sections[0],
    )

    assert _issues_for(bundle, "BRIEF_CANONICAL_SECTION_ORDER_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_CANONICAL_SECTION_ORDER_INVALID",
            "path": "brief.sections",
            "message": (
                "Canonical sections must appear in this order: Key Requirements; "
                "Penalties and Enforcement; Implementation Workplan."
            ),
            "related_ids": [
                "key_requirements",
                "penalties_enforcement",
                "implementation",
            ],
        }
    ]


def test_supported_requirement_must_appear_in_key_requirements() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    requirement_block = bundle.brief.sections[0].blocks[0]
    requirement_block.purpose = BriefBlockPurpose.APPLICATION
    requirement_block.items[0].finding_ids = []
    requirement_block.items[0].claim_ids = []

    assert _issues_for(bundle, "BRIEF_REQUIREMENT_FINDING_MISPLACED") == [
        {
            "level": "error",
            "code": "BRIEF_REQUIREMENT_FINDING_MISPLACED",
            "path": "brief.sections[0]",
            "message": (
                "Every supported requirements finding must appear in the "
                "Key Requirements section."
            ),
            "related_ids": ["finding-1"],
        }
    ]


def test_supported_enforcement_finding_must_appear_in_penalties_section() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
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
    bundle.brief.executive_summary.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            text="The rule provides an enforcement consequence.",
            finding_ids=[enforcement_finding.finding_id],
        )
    )

    assert _issues_for(bundle, "BRIEF_ENFORCEMENT_FINDING_MISPLACED") == [
        {
            "level": "error",
            "code": "BRIEF_ENFORCEMENT_FINDING_MISPLACED",
            "path": "brief.sections[1]",
            "message": (
                "Every supported enforcement finding must appear in the "
                "Penalties and Enforcement section."
            ),
            "related_ids": ["finding-enforcement"],
        }
    ]


def test_profiled_legal_analysis_requires_exact_claim_binding() -> None:
    """A finding-level marker must not validate fabricated legal prose."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    summary = bundle.brief.executive_summary[0]
    summary.text = (
        "The rule imposes a billion-dollar civil penalty for every recordkeeping error."
    )

    issues = validate_bundle(bundle).issues

    assert any(
        issue.code == "BRIEF_LEGAL_ANALYSIS_TEXT_UNSUPPORTED"
        and issue.path == "brief.executive_summary[0]"
        for issue in issues
    )


def test_profiled_legal_analysis_rejects_missing_unknown_and_wrong_finding_claims() -> None:
    """Claim identifiers must resolve to cited source claims owned by the stated finding."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    summary = bundle.brief.executive_summary[0]
    summary.claim_ids = []
    requirement_item = bundle.brief.sections[0].blocks[0].items[0]
    requirement_item.claim_ids = ["claim-missing"]

    other_finding = bundle.findings[0].model_copy(
        update={
            "finding_id": "finding-other",
            "claims": [
                bundle.findings[0].claims[0].model_copy(
                    update={"claim_id": "claim-other"}
                )
            ],
        }
    )
    bundle.findings.append(other_finding)
    requirement_item.claim_ids.append("claim-other")

    codes = {issue.code for issue in validate_bundle(bundle).issues}

    assert "BRIEF_LEGAL_ANALYSIS_CLAIM_MISSING" in codes
    assert "BRIEF_CLAIM_MISSING" in codes
    assert "BRIEF_CLAIM_FINDING_MISMATCH" in codes


def test_profiled_legal_analysis_can_derive_finding_from_bound_claim() -> None:
    """Claim ownership may supply the finding without weakening exact claim binding."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.executive_summary[0].finding_ids = []

    codes = {issue.code for issue in validate_bundle(bundle).issues}

    assert "BRIEF_LEGAL_ANALYSIS_CLAIM_MISSING" not in codes
    assert "BRIEF_CLAIM_FINDING_MISMATCH" not in codes
    assert "BRIEF_LEGAL_ANALYSIS_UNSUPPORTED" not in codes


def test_profiled_legal_analysis_rejects_non_evidentiary_bound_claim() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.findings[0].claims[0].kind = ClaimKind.ANALYSIS

    issues = _issues_for(bundle, "BRIEF_CLAIM_EVIDENCE_INVALID")

    assert issues[0]["related_ids"] == ["claim-1"]


def test_penalties_section_rejects_operational_content_and_requires_claim_pair() -> None:
    """The enforcement anchor must state supported law as trigger and consequence."""
    bundle = _bundle()
    bundle.brief = _profiled_brief()
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
    penalty = bundle.brief.sections[1].blocks[0]
    penalty.purpose = BriefBlockPurpose.APPLICATION
    penalty.text = "Route violations to the response team."
    penalty.finding_ids = [enforcement_finding.finding_id]
    penalty.claim_ids = ["claim-enforcement"]

    codes = {issue.code for issue in validate_bundle(bundle).issues}

    assert "BRIEF_PENALTIES_PURPOSE_INVALID" in codes

    penalty.purpose = BriefBlockPurpose.LEGAL_ANALYSIS
    penalty.text = "A controller must document material deployment risks."
    codes = {issue.code for issue in validate_bundle(bundle).issues}
    assert "BRIEF_ENFORCEMENT_PAIR_MISSING" in codes

    penalty.enforcement_trigger_claim_ids = ["claim-enforcement"]
    penalty.enforcement_consequence_claim_ids = ["claim-enforcement"]
    codes = {issue.code for issue in validate_bundle(bundle).issues}
    assert "BRIEF_ENFORCEMENT_PAIR_MISSING" not in codes
    assert "BRIEF_ENFORCEMENT_ROLE_INVALID" in codes

    enforcement_finding.claims[0] = Claim.model_validate(
        {
            **enforcement_finding.claims[0].model_dump(mode="json"),
            "enforcement_roles": ["trigger", "consequence"],
        }
    )
    codes = {issue.code for issue in validate_bundle(bundle).issues}
    assert "BRIEF_ENFORCEMENT_PAIR_INVALID" not in codes
    assert "BRIEF_ENFORCEMENT_ROLE_INVALID" not in codes


def test_gap_only_canonical_section_requires_not_established_limitation() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.brief.sections[1].blocks[0].text = "Enforcement terms remain unresolved."

    assert _issues_for(bundle, "BRIEF_NOT_ESTABLISHED_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_NOT_ESTABLISHED_MISSING",
            "path": "brief.sections[1]",
            "message": (
                "A canonical section with no supported category finding must include "
                "limitation content beginning 'Not established:'."
            ),
            "related_ids": ["enforcement"],
        }
    ]


def test_gap_only_canonical_section_requires_matching_categorized_gap() -> None:
    bundle = _bundle()
    bundle.brief = _profiled_brief()
    bundle.gaps = [
        gap for gap in bundle.gaps if gap.category is not IssueCategory.ENFORCEMENT
    ]

    assert _issues_for(bundle, "BRIEF_NOT_ESTABLISHED_GAP_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_NOT_ESTABLISHED_GAP_MISSING",
            "path": "gaps",
            "message": (
                "A canonical section with no supported category finding requires a "
                "matching categorized gap."
            ),
            "related_ids": ["enforcement"],
        }
    ]


@pytest.mark.parametrize(
    "text",
    [
        "The packet establishes the documentation duty.",
        "The materials collected indicate that documentation is required.",
        "Retained sources show that documentation is required.",
        "The retained authority establishes the documentation duty.",
        "The retained EUR-Lex materials show that the Act applies.",
        "The retained official public act and later compilation establish the duty.",
        "Two retained secondary sources identify a private right of action.",
        "The official summary gives May 2 as the application date.",
    ],
)
def test_validation_rejects_source_framed_legal_analysis_leads(text: str) -> None:
    """A legal memo must state the supported rule instead of narrating its packet."""
    bundle = _bundle()
    bundle.brief = _brief()
    bundle.brief.executive_summary[0].text = text

    report = validate_bundle(bundle)

    issues = [
        issue
        for issue in report.issues
        if issue.code == "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS"
    ]
    assert len(issues) == 1
    assert issues[0].path == "brief.executive_summary[0]"


@pytest.mark.parametrize(
    "text",
    [
        "The Example Rule requires controllers to document material risks.",
        "The retained earnings rule limits distributions.",
        "The material requirement applies before deployment.",
        "The materials collected by a covered entity must be destroyed within 30 days.",
        "The official summary must accompany the application.",
    ],
)
def test_validation_accepts_direct_regulation_centered_legal_analysis(
    text: str,
) -> None:
    """A direct supported rule is the intended attorney-facing narrative."""
    bundle = _bundle()
    bundle.brief = _brief()
    bundle.brief.executive_summary[0].text = text

    assert "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS" not in _codes(bundle)


def test_validation_allows_source_sufficiency_language_in_a_limitation() -> None:
    """Closed-universe limits remain explicit when they are typed as limits."""
    bundle = _bundle()
    bundle.brief = _brief()
    bundle.brief.executive_summary.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LIMITATION,
            text="The retained materials do not establish currentness.",
        )
    )

    assert "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS" not in _codes(bundle)


def test_validation_requires_a_legal_analysis_executive_summary_lead() -> None:
    """An evidence caveat must not displace the regulation from the memo lead."""
    bundle = _bundle()
    bundle.brief = _brief()
    bundle.brief.executive_summary.insert(
        0,
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LIMITATION,
            text="The retained materials do not establish currentness.",
        ),
    )

    report = validate_bundle(bundle)

    issues = [
        issue
        for issue in report.issues
        if issue.code == "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL"
    ]
    assert len(issues) == 1
    assert issues[0].path == "brief.executive_summary[0]"


@pytest.mark.parametrize(
    ("kind", "expected_path"),
    [
        ("list", "brief.sections[0].blocks[1].items[0]"),
        ("table", "brief.sections[0].blocks[1].rows[0]"),
        ("table_later_cell", "brief.sections[0].blocks[1].rows[0]"),
    ],
)
def test_validation_checks_source_framing_in_structured_legal_units(
    kind: str, expected_path: str
) -> None:
    """Lists and tables must not bypass the direct legal-voice contract."""
    bundle = _bundle()
    bundle.brief = _brief()
    if kind == "list":
        block = BriefBlock(
            kind=BriefBlockKind.BULLET_LIST,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            items=[
                BriefItem(
                    text="The source packet establishes the duty.",
                    finding_ids=["finding-1"],
                )
            ],
        )
    else:
        cells = (
            ["Rule", "The retained text establishes the duty."]
            if kind == "table_later_cell"
            else ["The retained text establishes the duty.", "Document risks"]
        )
        block = BriefBlock(
            kind=BriefBlockKind.TABLE,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            columns=["Rule", "Effect"],
            rows=[
                BriefTableRow(
                    cells=cells,
                    finding_ids=["finding-1"],
                )
            ],
        )
    bundle.brief.sections[0].blocks.append(block)

    report = validate_bundle(bundle)

    issues = [
        issue
        for issue in report.issues
        if issue.code == "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS"
    ]
    assert len(issues) == 1
    assert issues[0].path == expected_path


@pytest.mark.parametrize(
    "mutate",
    ["paragraph", "list_item", "table_row"],
)
def test_validation_rejects_unknown_finding_references_in_every_brief_unit(
    mutate: str,
) -> None:
    """A prose, list, or table citation must not point outside the evidence graph."""
    bundle = _bundle()
    brief = _brief()
    if mutate == "paragraph":
        brief.executive_summary[0].finding_ids = ["finding-missing"]
    elif mutate == "list_item":
        brief.sections[0].blocks[0].items[0].finding_ids = ["finding-missing"]
    else:
        brief.sections[0].subsections = [
            BriefSubsection(
                subsection_id="table",
                title="Decision Table",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.TABLE,
                        purpose=BriefBlockPurpose.APPLICATION,
                        columns=["Question", "Answer"],
                        rows=[
                            BriefTableRow(
                                cells=["Is documentation required?", "Yes"],
                                finding_ids=["finding-missing"],
                            )
                        ],
                    )
                ],
            )
        ]
    bundle.brief = brief

    report = validate_bundle(bundle)

    assert report.valid is False
    missing = [issue for issue in report.issues if issue.code == "BRIEF_FINDING_MISSING"]
    assert len(missing) == 1
    assert missing[0].related_ids == ["finding-missing"]


def test_validation_rejects_legal_analysis_without_resolved_evidence() -> None:
    """Labeling unsupported prose legal analysis would overstate deterministic grounding."""
    bundle = _bundle()
    bundle.findings.append(
        Finding(
            finding_id="finding-analysis-only",
            issue_id="issue-1",
            title="Suggested implementation",
            jurisdiction="US",
            authority="Attorney analysis",
            severity=Severity.INFO,
            practical_implication="Consider a review workflow.",
            claims=[
                Claim(
                    claim_id="claim-analysis-only",
                    text="Counsel should consider a review workflow.",
                    kind=ClaimKind.ANALYSIS,
                )
            ],
        )
    )
    brief = _brief()
    brief.executive_summary[0].finding_ids = ["finding-analysis-only"]
    bundle.brief = brief

    report = validate_bundle(bundle)

    assert report.valid is False
    unsupported = [
        issue
        for issue in report.issues
        if issue.code == "BRIEF_LEGAL_ANALYSIS_UNSUPPORTED"
    ]
    assert len(unsupported) == 1
    assert unsupported[0].related_ids == ["finding-analysis-only"]


def test_validation_rejects_supported_finding_omitted_from_brief() -> None:
    """A complete claim ledger must not be silently narrowed in the attorney report."""
    bundle = _bundle()
    bundle.brief = AttorneyBrief(
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.APPLICATION,
                text="Review the retained materials.",
            )
        ],
        sections=[
            BriefSection(
                section_id="next-steps",
                title="Next Steps",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Confirm the client facts.",
                    )
                ],
            )
        ],
    )

    report = validate_bundle(bundle)

    assert report.valid is False
    omitted = [issue for issue in report.issues if issue.code == "BRIEF_FINDING_OMITTED"]
    assert len(omitted) == 1
    assert omitted[0].related_ids == ["finding-1"]


def test_validation_detects_duplicate_section_ids_after_bundle_mutation() -> None:
    """Post-parse mutation must not bypass stable section identity checks."""
    bundle = _bundle()
    bundle.brief = _brief()
    bundle.brief.sections.append(bundle.brief.sections[0].model_copy(deep=True))

    report = validate_bundle(bundle)

    assert report.valid is False
    assert "BRIEF_SECTION_DUPLICATE" in {issue.code for issue in report.issues}


def test_validation_rejects_a_missing_attorney_coverage_dimension() -> None:
    """A terminal bundle must not silently omit a required attorney question."""
    bundle = _bundle()
    bundle.gaps = [
        gap for gap in bundle.gaps if gap.category is not IssueCategory.ENFORCEMENT
    ]

    report = validate_bundle(bundle)

    assert report.valid is False
    missing = [
        issue for issue in report.issues if issue.code == "COVERAGE_DIMENSION_MISSING"
    ]
    assert len(missing) == 1
    assert missing[0].related_ids == ["enforcement"]


def test_terminal_bundle_hash_excludes_itself_and_detects_tampering() -> None:
    """A self-referential or unchecked digest would not protect portable exports."""
    bundle = _bundle()
    bundle.bundle_hash = calculate_bundle_hash(bundle)

    assert calculate_bundle_hash(bundle) == bundle.bundle_hash
    assert validate_bundle(bundle, require_bundle_hash=True).valid is True

    bundle.request.question = "A changed question"
    report = validate_bundle(bundle, require_bundle_hash=True)
    assert report.valid is False
    assert {issue.code for issue in report.issues} >= {"BUNDLE_HASH_MISMATCH"}


def test_new_bundle_uses_current_schema_and_hashes_every_current_field() -> None:
    bundle = _bundle()

    assert bundle.schema_version == "1.1"
    bundle.bundle_hash = calculate_bundle_hash(bundle)
    original_hash = bundle.bundle_hash
    bundle.request.matter_title = "A changed current-schema field"

    assert calculate_bundle_hash(bundle) != original_hash
    assert "BUNDLE_HASH_MISMATCH" in _codes(bundle)


def test_genuine_schema_10_bundle_verifies_against_historical_projection() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)

    loaded = ResearchBundle.model_validate(historical)
    report = validate_bundle(loaded, require_bundle_hash=True)

    assert loaded.schema_version == "1.0"
    assert {issue.code for issue in report.issues}.isdisjoint(
        {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
    )


def test_initial_release_schema_10_bundle_verifies_against_its_exact_shape() -> None:
    historical = _historical_schema_10_payload(
        _bundle(),
        initial_release_shape=True,
    )
    historical["bundle_hash"] = _historical_hash(historical)

    loaded = ResearchBundle.model_validate(historical)
    report = validate_bundle(loaded, require_bundle_hash=True)

    assert "source_mode" not in loaded.request.model_fields_set
    assert all(
        {"publisher", "effective_date", "supersession"}.isdisjoint(
            source_input.model_fields_set
        )
        for source_input in loaded.request.source_inputs
    )
    assert {issue.code for issue in report.issues}.isdisjoint(
        {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
    )


def test_schema_10_hash_preserves_nondefault_fields_from_original_contract() -> None:
    bundle = _bundle()
    bundle.request.source_mode = "web"
    source_input = bundle.request.source_inputs[0]
    source_input.publisher = "Original publisher"
    source_input.effective_date = "2026-01-01"
    source_input.supersession = "Supersedes the 2025 edition"
    historical = _historical_schema_10_payload(bundle)
    historical["bundle_hash"] = _historical_hash(historical)

    report = validate_bundle(
        ResearchBundle.model_validate(historical),
        require_bundle_hash=True,
    )

    assert {issue.code for issue in report.issues}.isdisjoint(
        {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
    )


def test_schema_10_tampering_still_fails_historical_hash_verification() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)
    historical["request"]["question"] = "Tampered question"

    report = validate_bundle(
        ResearchBundle.model_validate(historical),
        require_bundle_hash=True,
    )

    assert "BUNDLE_HASH_MISMATCH" in {issue.code for issue in report.issues}


def test_schema_10_cannot_hide_nondefault_post_10_fields_from_legacy_hash() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)
    historical["request"]["matter_title"] = "Post-1.0 content"

    report = validate_bundle(
        ResearchBundle.model_validate(historical),
        require_bundle_hash=True,
    )

    assert "BUNDLE_SCHEMA_CONTENT_INVALID" in {
        issue.code for issue in report.issues
    }


def test_schema_10_rejects_a_mixed_historical_field_shape() -> None:
    historical = _historical_schema_10_payload(
        _bundle(),
        initial_release_shape=True,
    )
    historical["request"]["source_inputs"][0]["publisher"] = None
    historical["bundle_hash"] = _historical_hash(historical)

    report = validate_bundle(
        ResearchBundle.model_validate(historical),
        require_bundle_hash=True,
    )

    assert "BUNDLE_SCHEMA_CONTENT_INVALID" in {
        issue.code for issue in report.issues
    }


def test_schema_10_bundle_migrates_to_current_hash_contract() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)
    legacy = ResearchBundle.model_validate(historical)

    migrated = migrate_bundle_hash_contract(legacy)

    assert migrated.schema_version == "1.1"
    assert migrated.bundle_hash == calculate_bundle_hash(migrated)
    assert _codes(migrated).isdisjoint(
        {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
    )


def test_mixed_schema_10_and_11_bundles_verify_without_downgrade() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)
    current = _bundle()
    current.bundle_hash = calculate_bundle_hash(current)

    reports = [
        validate_bundle(bundle, require_bundle_hash=True)
        for bundle in (ResearchBundle.model_validate(historical), current)
    ]

    assert all(
        {issue.code for issue in report.issues}.isdisjoint(
            {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
        )
        for report in reports
    )


def test_evaluator_native_controls_accept_both_bundle_hash_contracts() -> None:
    historical = _historical_schema_10_payload(_bundle())
    historical["bundle_hash"] = _historical_hash(historical)
    current = _bundle()
    current.bundle_hash = calculate_bundle_hash(current)

    for payload in (
        ResearchBundle.model_validate(historical).model_dump(mode="json"),
        current.model_dump(mode="json"),
    ):
        report_text = "Synthetic report."
        checks = _derive_deterministic_checks(
            CandidateReport(
                candidate_id="synthetic-candidate",
                role=CandidateRole.CANDIDATE,
                report_text=report_text,
                report_hash=sha256_digest(report_text.encode("utf-8")),
                bundle_json=payload,
                validation_receipt={"kind": "external"},
            ),
            "A",
        )

        assert set(checks.critical_codes).isdisjoint(
            {"BUNDLE_HASH_MISMATCH", "BUNDLE_SCHEMA_CONTENT_INVALID"}
        )


def test_terminal_bundle_requires_hash_when_requested() -> None:
    """Missing integrity metadata must fail at public export boundaries."""
    report = validate_bundle(_bundle(), require_bundle_hash=True)

    assert report.valid is False
    assert {issue.code for issue in report.issues} >= {"BUNDLE_HASH_MISSING"}


def test_validation_detects_changed_source_content() -> None:
    """Trusting a stored hash without recomputing it would miss source drift."""
    bundle = _bundle()
    bundle.sources[0].normalized_text += " Altered."
    assert "SOURCE_HASH_MISMATCH" in _codes(bundle)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_source", "CITATION_SOURCE_MISSING"),
        ("out_of_bounds", "CITATION_BOUNDS_INVALID"),
        ("quote_mismatch", "QUOTE_MISMATCH"),
        ("duplicate_citation", "CITATION_ID_DUPLICATE"),
        ("uncited_material_claim", "MATERIAL_CLAIM_UNCITED"),
        ("missing_jurisdiction", "JURISDICTION_UNCOVERED"),
    ],
)
def test_validation_detects_broken_evidence_graph(
    mutation: str, expected_code: str
) -> None:
    """Removing the corresponding graph invariant would hide this defect."""
    bundle = _bundle()
    if mutation == "missing_source":
        bundle.citations[0].source_id = "src_missing"
    elif mutation == "out_of_bounds":
        bundle.citations[0].end_char = len(TEXT) + 100
    elif mutation == "quote_mismatch":
        bundle.citations[0].quote = "must ignore material deployment risks"
    elif mutation == "duplicate_citation":
        bundle.citations.append(bundle.citations[0].model_copy(deep=True))
    elif mutation == "uncited_material_claim":
        bundle.findings[0].claims[0].citation_ids = []
    elif mutation == "missing_jurisdiction":
        bundle.request.jurisdictions.append("CA")
    assert expected_code in _codes(bundle)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("request_run", "REQUEST_RUN_ID_MISMATCH"),
        ("generator", "GENERATOR_VERSION_MISMATCH"),
        ("missing_issue", "FINDING_ISSUE_MISSING"),
        ("duplicate_issue", "ISSUE_ID_DUPLICATE"),
        ("duplicate_finding", "FINDING_ID_DUPLICATE"),
        ("duplicate_claim", "CLAIM_ID_DUPLICATE"),
    ],
)
def test_validation_detects_broken_provenance_links(
    mutation: str, expected_code: str
) -> None:
    """Portable bundles need stable identities and resolvable evidence relationships."""
    bundle = _bundle()
    if mutation == "request_run":
        bundle.manifest.run_id = "another-run"
    elif mutation == "generator":
        bundle.manifest.generator_version = "9.9.9"
    elif mutation == "missing_issue":
        bundle.findings[0].issue_id = "missing-issue"
    elif mutation == "duplicate_issue":
        bundle.issues.append(bundle.issues[0].model_copy(deep=True))
    elif mutation == "duplicate_finding":
        bundle.findings.append(bundle.findings[0].model_copy(deep=True))
    elif mutation == "duplicate_claim":
        bundle.findings[0].claims.append(
            bundle.findings[0].claims[0].model_copy(deep=True)
        )

    assert expected_code in _codes(bundle)


def test_failed_source_requires_explicit_gap() -> None:
    """Silently dropping a failed fetch would make absence look like no applicable law."""
    bundle = _bundle()
    failed = SourceRecord(
        source_id="src_failed",
        origin="https://example.invalid/rule",
        display_name="Unavailable Rule",
        retrieved_at=NOW,
        content_hash=None,
        media_type="application/octet-stream",
        normalized_text="",
        source_quality=SourceQuality.UNUSABLE,
        fetch_status=FetchStatus.FAILED,
        error=SourceFailure(category="network_error", retryable=True, message="unavailable"),
    )
    bundle.sources.append(failed)
    assert "FAILED_SOURCE_UNACKNOWLEDGED" in _codes(bundle)

    bundle.gaps.append(
        Gap(
            gap_id="gap-failed",
            code="SOURCE_FETCH_FAILED",
            message="The supplied source could not be retrieved.",
            source_ids=[failed.source_id],
        )
    )
    assert "FAILED_SOURCE_UNACKNOWLEDGED" not in _codes(bundle)


def test_web_mode_requires_a_successfully_retained_primary_authority() -> None:
    """Web research must not look complete when discovery found only secondary material."""
    bundle = _bundle()
    bundle.request.source_mode = "web"
    bundle.sources[0].source_quality = SourceQuality.SECONDARY

    report = validate_bundle(bundle)

    assert report.valid is False
    assert "WEB_PRIMARY_AUTHORITY_MISSING" in {issue.code for issue in report.issues}


def test_failed_primary_source_does_not_satisfy_web_authority_gate() -> None:
    """A primary label is not useful if the authority was never successfully retained."""
    bundle = _bundle()
    bundle.request.source_mode = "web"
    bundle.sources[0].fetch_status = FetchStatus.FAILED
    bundle.sources[0].error = SourceFailure(
        category="network_error", retryable=True, message="unavailable"
    )
    bundle.gaps.append(
        Gap(
            gap_id="gap-primary-fetch",
            code="SOURCE_FETCH_FAILED",
            message="The primary authority could not be retrieved.",
            source_ids=[bundle.sources[0].source_id],
        )
    )

    assert "WEB_PRIMARY_AUTHORITY_MISSING" in _codes(bundle)


def test_successful_primary_source_satisfies_web_authority_gate() -> None:
    """Web research may proceed when at least one primary authority was retained."""
    bundle = _bundle()
    bundle.request.source_mode = "web"

    assert "WEB_PRIMARY_AUTHORITY_MISSING" not in _codes(bundle)


def test_provided_only_mode_does_not_require_primary_authority() -> None:
    """A closed universe may intentionally contain only secondary supplied material."""
    bundle = _bundle()
    bundle.sources[0].source_quality = SourceQuality.SECONDARY

    assert "WEB_PRIMARY_AUTHORITY_MISSING" not in _codes(bundle)


def test_missing_source_metadata_produces_reviewable_warnings() -> None:
    """Thin provenance must remain visible even when the evidence graph is otherwise valid."""
    bundle = _bundle()
    bundle.sources[0].source_quality = SourceQuality.UNKNOWN
    report = validate_bundle(bundle)
    warnings = {issue.code for issue in report.issues if issue.level == "warning"}

    assert warnings >= {
        "SOURCE_AUTHORITY_TYPE_MISSING",
        "SOURCE_CANONICAL_URL_MISSING",
        "SOURCE_PUBLISHER_MISSING",
        "SOURCE_QUALITY_UNVERIFIED",
    }


def test_blank_source_metadata_does_not_bypass_provenance_warnings() -> None:
    """Whitespace placeholders are not meaningful provenance."""
    bundle = _bundle()
    bundle.sources[0].publisher = ""
    bundle.sources[0].jurisdiction = "   "
    bundle.sources[0].authority_type = "\t"

    warnings = {issue.code for issue in validate_bundle(bundle).issues}

    assert warnings >= {
        "SOURCE_AUTHORITY_TYPE_MISSING",
        "SOURCE_JURISDICTION_MISSING",
        "SOURCE_PUBLISHER_MISSING",
    }


def test_gap_source_identifiers_must_resolve() -> None:
    """A gap must not preserve provenance links to sources outside the bundle."""
    bundle = _bundle()
    bundle.gaps.append(
        Gap(
            gap_id="gap-missing-source",
            code="PRIMARY_AUTHORITY_UNAVAILABLE",
            message="A source was unavailable.",
            source_ids=["src_missing"],
        )
    )

    report = validate_bundle(bundle)

    assert report.valid is False
    assert "GAP_SOURCE_MISSING" in {issue.code for issue in report.issues}


def test_validation_issues_have_stable_sort_order() -> None:
    """Filesystem or set iteration order would make reports non-reproducible."""
    bundle = _bundle()
    bundle.request.jurisdictions.extend(["GB", "CA"])
    report = validate_bundle(bundle)
    keys = [(issue.level.value, issue.code, issue.path) for issue in report.issues]
    assert keys == sorted(keys)
