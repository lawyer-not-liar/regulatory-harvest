"""Deterministic evidence-bundle validation."""

import re
from collections import Counter
from datetime import UTC, datetime

from regulatory_harvest.models import (
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    BriefSectionRole,
    BriefStructureProfile,
    Claim,
    ClaimKind,
    EnforcementClaimRole,
    FetchStatus,
    IssueCategory,
    IssueLevel,
    ResearchBundle,
    SupportStatus,
    ValidationIssue,
    ValidationReport,
)
from regulatory_harvest.models.enums import REQUIRED_ISSUE_CATEGORIES
from regulatory_harvest.storage import calculate_bundle_hash, sha256_digest

from .citations import resolve_quote
from .support import check_claim_support

_SOURCE_FRAMED_LEGAL_LEAD = re.compile(
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


def _issue(
    level: IssueLevel,
    code: str,
    path: str,
    message: str,
    *related_ids: str,
) -> ValidationIssue:
    return ValidationIssue(
        level=level,
        code=code,
        path=path,
        message=message,
        related_ids=list(related_ids),
    )


def _duplicate_issues(
    identifiers: list[str], code: str, path: str
) -> list[ValidationIssue]:
    return [
        _issue(
            IssueLevel.ERROR,
            code,
            path,
            f"Identifier {identifier!r} occurs more than once.",
            identifier,
        )
        for identifier, count in Counter(identifiers).items()
        if count > 1
    ]


def _brief_units(
    bundle: ResearchBundle,
) -> list[
    tuple[
        str,
        BriefBlockPurpose,
        tuple[str, ...],
        list[str],
        list[str],
        list[str],
        list[str],
    ]
]:
    if bundle.brief is None:
        return []

    units: list[
        tuple[
            str,
            BriefBlockPurpose,
            tuple[str, ...],
            list[str],
            list[str],
            list[str],
            list[str],
        ]
    ] = []

    def add_block(path: str, block: BriefBlock) -> None:
        if block.kind is BriefBlockKind.PARAGRAPH:
            assert block.text is not None
            units.append(
                (
                    path,
                    block.purpose,
                    (block.text,),
                    block.finding_ids,
                    block.claim_ids,
                    block.enforcement_trigger_claim_ids,
                    block.enforcement_consequence_claim_ids,
                )
            )
            return
        if block.kind in {BriefBlockKind.BULLET_LIST, BriefBlockKind.NUMBERED_LIST}:
            units.extend(
                (
                    f"{path}.items[{index}]",
                    block.purpose,
                    (item.text,),
                    item.finding_ids,
                    item.claim_ids,
                    item.enforcement_trigger_claim_ids,
                    item.enforcement_consequence_claim_ids,
                )
                for index, item in enumerate(block.items)
            )
            return
        units.extend(
            (
                f"{path}.rows[{index}]",
                block.purpose,
                tuple(row.cells),
                row.finding_ids,
                row.claim_ids,
                row.enforcement_trigger_claim_ids,
                row.enforcement_consequence_claim_ids,
            )
            for index, row in enumerate(block.rows)
        )

    for block_index, block in enumerate(bundle.brief.executive_summary):
        add_block(f"brief.executive_summary[{block_index}]", block)
    for section_index, section in enumerate(bundle.brief.sections):
        section_path = f"brief.sections[{section_index}]"
        for block_index, block in enumerate(section.blocks):
            add_block(f"{section_path}.blocks[{block_index}]", block)
        for subsection_index, subsection in enumerate(section.subsections):
            subsection_path = f"{section_path}.subsections[{subsection_index}]"
            for block_index, block in enumerate(subsection.blocks):
                add_block(f"{subsection_path}.blocks[{block_index}]", block)
    return units


_CANONICAL_BRIEF_SECTIONS = (
    (
        BriefSectionRole.KEY_REQUIREMENTS,
        "Key Requirements",
        IssueCategory.REQUIREMENTS,
    ),
    (
        BriefSectionRole.PENALTIES_ENFORCEMENT,
        "Penalties and Enforcement",
        IssueCategory.ENFORCEMENT,
    ),
    (
        BriefSectionRole.IMPLEMENTATION,
        "Implementation Workplan",
        None,
    ),
)


def _profiled_brief_issues(
    bundle: ResearchBundle,
    supported_finding_ids: set[str],
    category_by_issue_id: dict[str, IssueCategory],
    claim_finding_by_id: dict[str, str],
    enforcement_roles_by_claim_id: dict[str, set[EnforcementClaimRole]],
) -> list[ValidationIssue]:
    brief = bundle.brief
    if (
        brief is None
        or brief.structure_profile is not BriefStructureProfile.REGULATORY_WALK_V1
    ):
        return []

    issues: list[ValidationIssue] = []
    if (
        bundle.request.matter_title is None
        or not bundle.request.matter_title.strip()
    ):
        issues.append(
            _issue(
                IssueLevel.ERROR,
                "BRIEF_MATTER_TITLE_MISSING",
                "request.matter_title",
                "A profiled attorney brief requires a concrete matter title.",
                BriefStructureProfile.REGULATORY_WALK_V1.value,
            )
        )
    sections_by_role: dict[BriefSectionRole, list[int]] = {
        role: [] for role, _, _ in _CANONICAL_BRIEF_SECTIONS
    }
    canonical_role_by_title = {
        title: role for role, title, _ in _CANONICAL_BRIEF_SECTIONS
    }
    for section_index, section in enumerate(brief.sections):
        if section.role is None:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_SECTION_ROLE_MISSING",
                    f"brief.sections[{section_index}].role",
                    "Every section in a profiled attorney brief must declare a semantic role.",
                    section.section_id,
                )
            )
            continue
        reserved_role = canonical_role_by_title.get(section.title)
        if section.role is BriefSectionRole.OTHER and reserved_role is not None:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
                    f"brief.sections[{section_index}].title",
                    "Canonical heading may be used only by its matching section role.",
                    reserved_role.value,
                )
            )
        if section.role in sections_by_role:
            sections_by_role[section.role].append(section_index)

    canonical_index_by_role: dict[BriefSectionRole, int] = {}
    for role, title, _ in _CANONICAL_BRIEF_SECTIONS:
        matching_indexes = sections_by_role[role]
        if not matching_indexes:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_CANONICAL_SECTION_MISSING",
                    "brief.sections",
                    "Profiled attorney brief is missing a required canonical section.",
                    role.value,
                )
            )
            continue
        if len(matching_indexes) > 1:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_CANONICAL_SECTION_DUPLICATE",
                    "brief.sections",
                    "Profiled attorney brief contains a canonical section role more than once.",
                    role.value,
                )
            )
            continue
        section_index = matching_indexes[0]
        canonical_index_by_role[role] = section_index
        if brief.sections[section_index].title != title:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_CANONICAL_SECTION_TITLE_INVALID",
                    f"brief.sections[{section_index}].title",
                    "Canonical section role must use its required heading.",
                    role.value,
                )
            )

    canonical_roles = tuple(role for role, _, _ in _CANONICAL_BRIEF_SECTIONS)
    if all(role in canonical_index_by_role for role in canonical_roles):
        canonical_indexes = [canonical_index_by_role[role] for role in canonical_roles]
        if canonical_indexes != sorted(canonical_indexes):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_CANONICAL_SECTION_ORDER_INVALID",
                    "brief.sections",
                    "Canonical sections must appear in this order: Key Requirements; "
                    "Penalties and Enforcement; Implementation Workplan.",
                    *(role.value for role in canonical_roles),
                )
            )

    purpose_contracts = (
        (
            BriefSectionRole.KEY_REQUIREMENTS,
            {BriefBlockPurpose.LEGAL_ANALYSIS, BriefBlockPurpose.LIMITATION},
            "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
            "Key Requirements may contain only legal-analysis or limitation blocks.",
        ),
        (
            BriefSectionRole.PENALTIES_ENFORCEMENT,
            {BriefBlockPurpose.LEGAL_ANALYSIS, BriefBlockPurpose.LIMITATION},
            "BRIEF_PENALTIES_PURPOSE_INVALID",
            "Penalties and Enforcement may contain only legal-analysis or limitation blocks.",
        ),
        (
            BriefSectionRole.IMPLEMENTATION,
            {
                BriefBlockPurpose.APPLICATION,
                BriefBlockPurpose.CLIENT_FACT,
                BriefBlockPurpose.LIMITATION,
            },
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
        section = brief.sections[section_index]
        blocks = [
            (f"brief.sections[{section_index}].blocks[{index}]", block)
            for index, block in enumerate(section.blocks)
        ]
        for subsection_index, subsection in enumerate(section.subsections):
            blocks.extend(
                (
                    f"brief.sections[{section_index}].subsections[{subsection_index}]"
                    f".blocks[{block_index}]",
                    block,
                )
                for block_index, block in enumerate(subsection.blocks)
            )
        for block_path, block in blocks:
            if block.purpose not in allowed:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        code,
                        f"{block_path}.purpose",
                        message,
                        role.value,
                    )
                )

    finding_by_id = {finding.finding_id: finding for finding in bundle.findings}
    for role, _, category in _CANONICAL_BRIEF_SECTIONS:
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
            and category_by_issue_id.get(finding_by_id[finding_id].issue_id) is category
        )
        if category_finding_ids:
            misplaced_ids = sorted(set(category_finding_ids) - section_finding_ids)
            if misplaced_ids:
                code = (
                    "BRIEF_REQUIREMENT_FINDING_MISPLACED"
                    if category is IssueCategory.REQUIREMENTS
                    else "BRIEF_ENFORCEMENT_FINDING_MISPLACED"
                )
                message = (
                    "Every supported requirements finding must appear in the "
                    "Key Requirements section."
                    if category is IssueCategory.REQUIREMENTS
                    else "Every supported enforcement finding must appear in the "
                    "Penalties and Enforcement section."
                )
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        code,
                        section_path,
                        message,
                        *misplaced_ids,
                    )
                )
            continue

        has_not_established_limitation = any(
            purpose is BriefBlockPurpose.LIMITATION
            and any(text.strip().casefold().startswith("not established:") for text in texts)
            for _, purpose, texts, _, _, _, _ in section_units
        )
        if not has_not_established_limitation:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_NOT_ESTABLISHED_MISSING",
                    section_path,
                    "A canonical section with no supported category finding must include "
                    "limitation content beginning 'Not established:'.",
                    category.value,
                )
            )
        if not any(gap.category is category for gap in bundle.gaps):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_NOT_ESTABLISHED_GAP_MISSING",
                    "gaps",
                    "A canonical section with no supported category finding requires a "
                    "matching categorized gap.",
                    category.value,
                )
            )
    penalty_indexes = sections_by_role[BriefSectionRole.PENALTIES_ENFORCEMENT]
    if len(penalty_indexes) == 1:
        penalty_path = f"brief.sections[{penalty_indexes[0]}]"
        for path, purpose, _, _, claim_ids, trigger_ids, consequence_ids in _brief_units(
            bundle
        ):
            if (
                not path.startswith(f"{penalty_path}.")
                or purpose is not BriefBlockPurpose.LEGAL_ANALYSIS
            ):
                continue
            if not trigger_ids or not consequence_ids:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_ENFORCEMENT_PAIR_MISSING",
                        path,
                        "Supported penalties-and-enforcement analysis must bind both the "
                        "legal trigger and its consequence.",
                    )
                )
                continue
            claim_id_set = set(claim_ids)
            if not set(trigger_ids) <= claim_id_set or not set(consequence_ids) <= claim_id_set:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_ENFORCEMENT_PAIR_INVALID",
                        path,
                        "Enforcement trigger and consequence claims must be included in the "
                        "unit's bound claim identifiers.",
                        *sorted((set(trigger_ids) | set(consequence_ids)) - claim_id_set),
                    )
                )
                continue
            invalid_role_ids = sorted(
                {
                    claim_id
                    for claim_id in trigger_ids
                    if EnforcementClaimRole.TRIGGER
                    not in enforcement_roles_by_claim_id.get(claim_id, set())
                }
                | {
                    claim_id
                    for claim_id in consequence_ids
                    if EnforcementClaimRole.CONSEQUENCE
                    not in enforcement_roles_by_claim_id.get(claim_id, set())
                }
            )
            if invalid_role_ids:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_ENFORCEMENT_ROLE_INVALID",
                        path,
                        "Enforcement trigger and consequence bindings require matching "
                        "typed roles on each source-supported claim.",
                        *invalid_role_ids,
                    )
                )
    return issues


def validate_bundle(
    bundle: ResearchBundle, *, require_bundle_hash: bool = False
) -> ValidationReport:
    """Validate provenance, citation integrity, support signals, and coverage."""
    issues: list[ValidationIssue] = []
    if bundle.bundle_hash is None:
        if require_bundle_hash:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BUNDLE_HASH_MISSING",
                    "bundle_hash",
                    "Terminal bundle is missing its integrity hash.",
                )
            )
    else:
        try:
            expected_bundle_hash = calculate_bundle_hash(bundle)
        except ValueError:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BUNDLE_SCHEMA_CONTENT_INVALID",
                    "schema_version",
                    "Bundle content is not valid under its declared hash contract.",
                )
            )
        else:
            if bundle.bundle_hash != expected_bundle_hash:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BUNDLE_HASH_MISMATCH",
                        "bundle_hash",
                        "Stored bundle hash does not match the canonical bundle content.",
                    )
                )
    if bundle.request.request_id != bundle.manifest.run_id:
        issues.append(
            _issue(
                IssueLevel.ERROR,
                "REQUEST_RUN_ID_MISMATCH",
                "manifest.run_id",
                "Run manifest identifier does not match the research request.",
                bundle.request.request_id,
                bundle.manifest.run_id,
            )
        )
    if bundle.generator_version != bundle.manifest.generator_version:
        issues.append(
            _issue(
                IssueLevel.ERROR,
                "GENERATOR_VERSION_MISMATCH",
                "manifest.generator_version",
                "Run manifest generator version does not match the bundle.",
            )
        )
    issues.extend(
        _duplicate_issues(
            [source.source_id for source in bundle.sources],
            "SOURCE_ID_DUPLICATE",
            "sources",
        )
    )
    if bundle.brief is not None:
        if (
            bundle.brief.executive_summary[0].purpose
            is not BriefBlockPurpose.LEGAL_ANALYSIS
        ):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_EXECUTIVE_SUMMARY_LEAD_NONLEGAL",
                    "brief.executive_summary[0]",
                    "Executive Summary must begin with supported legal analysis about "
                    "the governing authority.",
                )
            )
        issues.extend(
            _duplicate_issues(
                [section.section_id for section in bundle.brief.sections],
                "BRIEF_SECTION_DUPLICATE",
                "brief.sections",
            )
        )
        for section_index, section in enumerate(bundle.brief.sections):
            issues.extend(
                _duplicate_issues(
                    [
                        subsection.subsection_id
                        for subsection in section.subsections
                    ],
                    "BRIEF_SUBSECTION_DUPLICATE",
                    f"brief.sections[{section_index}].subsections",
                )
            )
    issues.extend(
        _duplicate_issues(
            [citation.citation_id for citation in bundle.citations],
            "CITATION_ID_DUPLICATE",
            "citations",
        )
    )
    issues.extend(
        _duplicate_issues(
            [issue.issue_id for issue in bundle.issues],
            "ISSUE_ID_DUPLICATE",
            "issues",
        )
    )
    issues.extend(
        _duplicate_issues(
            [finding.finding_id for finding in bundle.findings],
            "FINDING_ID_DUPLICATE",
            "findings",
        )
    )
    issues.extend(
        _duplicate_issues(
            [claim.claim_id for finding in bundle.findings for claim in finding.claims],
            "CLAIM_ID_DUPLICATE",
            "findings[].claims",
        )
    )
    issues.extend(
        _duplicate_issues(
            [gap.gap_id for gap in bundle.gaps],
            "GAP_ID_DUPLICATE",
            "gaps",
        )
    )
    issues.extend(
        _duplicate_issues(
            [item.review_id for item in bundle.review_items],
            "REVIEW_ID_DUPLICATE",
            "review_items",
        )
    )

    source_by_id = {source.source_id: source for source in bundle.sources}
    citation_by_id = {citation.citation_id: citation for citation in bundle.citations}
    issue_ids = {issue.issue_id for issue in bundle.issues}
    finding_by_id = {finding.finding_id: finding for finding in bundle.findings}
    claim_by_id = {
        claim.claim_id: claim
        for finding in bundle.findings
        for claim in finding.claims
    }
    claim_finding_by_id = {
        claim.claim_id: finding.finding_id
        for finding in bundle.findings
        for claim in finding.claims
    }
    enforcement_roles_by_claim_id = {
        claim.claim_id: set(claim.enforcement_roles)
        for finding in bundle.findings
        for claim in finding.claims
    }
    supported_finding_ids = {
        finding.finding_id
        for finding in bundle.findings
        if any(
            claim.kind is ClaimKind.SOURCE_SUPPORTED
            and any(citation_id in citation_by_id for citation_id in claim.citation_ids)
            for claim in finding.claims
        )
    }
    category_by_issue_id = {issue.issue_id: issue.category for issue in bundle.issues}
    issues.extend(
        _profiled_brief_issues(
            bundle,
            supported_finding_ids,
            category_by_issue_id,
            claim_finding_by_id,
            enforcement_roles_by_claim_id,
        )
    )

    if bundle.brief is not None:
        used_finding_ids: set[str] = set()
        profiled = (
            bundle.brief.structure_profile is BriefStructureProfile.REGULATORY_WALK_V1
        )
        source_by_id_for_brief = {source.source_id: source for source in bundle.sources}
        for (
            path,
            purpose,
            texts,
            finding_ids,
            claim_ids,
            _,
            _,
        ) in _brief_units(bundle):
            if (
                purpose is BriefBlockPurpose.LEGAL_ANALYSIS
                and any(_SOURCE_FRAMED_LEGAL_LEAD.search(text) for text in texts)
            ):
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_SOURCE_FRAMED_LEGAL_ANALYSIS",
                        path,
                        "State the supported legal rule directly; reserve source-"
                        "sufficiency framing for limitation content.",
                    )
                )
            known_claim_ids = [claim_id for claim_id in claim_ids if claim_id in claim_by_id]
            if profiled and purpose is BriefBlockPurpose.LEGAL_ANALYSIS:
                if not claim_ids:
                    issues.append(
                        _issue(
                            IssueLevel.ERROR,
                            "BRIEF_LEGAL_ANALYSIS_CLAIM_MISSING",
                            f"{path}.claim_ids",
                            "Profiled legal analysis must bind exact source-supported claims.",
                        )
                    )
                for claim_id in claim_ids:
                    if claim_id in claim_by_id:
                        continue
                    issues.append(
                        _issue(
                            IssueLevel.ERROR,
                            "BRIEF_CLAIM_MISSING",
                            f"{path}.claim_ids",
                            "Attorney brief content references a claim outside the bundle.",
                            claim_id,
                        )
                    )

                bound_claims = [claim_by_id[claim_id] for claim_id in known_claim_ids]

                def has_exact_citations(claim: Claim) -> bool:
                    if not claim.citation_ids:
                        return False
                    for citation_id in claim.citation_ids:
                        citation = citation_by_id.get(citation_id)
                        if citation is None:
                            return False
                        source = source_by_id_for_brief.get(citation.source_id)
                        if source is None or (
                            source.normalized_text[
                                citation.start_char : citation.end_char
                            ]
                            != citation.quote
                        ):
                            return False
                    return True

                invalid_claim_ids = [
                    claim.claim_id
                    for claim in bound_claims
                    if claim.kind is not ClaimKind.SOURCE_SUPPORTED
                    or not has_exact_citations(claim)
                ]
                if invalid_claim_ids:
                    issues.append(
                        _issue(
                            IssueLevel.ERROR,
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
                        _issue(
                            IssueLevel.ERROR,
                            "BRIEF_CLAIM_FINDING_MISMATCH",
                            path,
                            "Bound claims must belong exactly to the referenced or derivable "
                            "findings.",
                            *sorted(set(finding_ids) ^ derived_finding_ids),
                        )
                    )

                exact_citations = []
                for claim in bound_claims:
                    for citation_id in claim.citation_ids:
                        citation = citation_by_id.get(citation_id)
                        if citation is None:
                            continue
                        source = source_by_id_for_brief.get(citation.source_id)
                        if source is None:
                            continue
                        if (
                            source.normalized_text[
                                citation.start_char : citation.end_char
                            ]
                            != citation.quote
                        ):
                            continue
                        exact_citations.append(citation)
                unit_text = " ".join(texts)
                normalized_unit = " ".join(unit_text.split()).casefold()
                normalized_claims = {
                    " ".join(claim.text.split()).casefold() for claim in bound_claims
                }
                combined_claims = " ".join(
                    " ".join(claim.text.split()) for claim in bound_claims
                ).casefold()
                lexical_support = check_claim_support(
                    Claim(
                        claim_id=f"brief-unit:{path}",
                        text=unit_text,
                        kind=ClaimKind.SOURCE_SUPPORTED,
                        citation_ids=[citation.citation_id for citation in exact_citations],
                    ),
                    exact_citations,
                    bundle.sources,
                )
                if bound_claims and (
                    normalized_unit not in normalized_claims
                    and normalized_unit != combined_claims
                    and lexical_support.status is not SupportStatus.SUPPORTED
                ):
                    issues.append(
                        _issue(
                            IssueLevel.ERROR,
                            "BRIEF_LEGAL_ANALYSIS_TEXT_UNSUPPORTED",
                            path,
                            "Legal-analysis prose must remain lexically anchored to its bound "
                            "claims; this check does not establish semantic entailment.",
                            *known_claim_ids,
                        )
                    )
                used_finding_ids.update(derived_finding_ids)
            missing_ids = [
                finding_id
                for finding_id in finding_ids
                if finding_id not in finding_by_id
            ]
            for finding_id in missing_ids:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_FINDING_MISSING",
                        f"{path}.finding_ids",
                        "Attorney brief content references a finding outside the bundle.",
                        finding_id,
                    )
                )
            known_ids = [
                finding_id
                for finding_id in finding_ids
                if finding_id in finding_by_id
            ]
            used_finding_ids.update(known_ids)
            unsupported_ids = [
                finding_id
                for finding_id in known_ids
                if finding_id not in supported_finding_ids
            ]
            if purpose is BriefBlockPurpose.LEGAL_ANALYSIS and not profiled and (
                not known_ids or unsupported_ids
            ):
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "BRIEF_LEGAL_ANALYSIS_UNSUPPORTED",
                        path,
                        "Legal-analysis content must reference findings with resolved evidence.",
                        *unsupported_ids,
                    )
                )
        for finding_id in sorted(supported_finding_ids - used_finding_ids):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "BRIEF_FINDING_OMITTED",
                    "brief",
                    "A source-supported finding is absent from the attorney brief.",
                    finding_id,
                )
            )

    if bundle.request.source_mode == "web" and not any(
        source.fetch_status is FetchStatus.SUCCEEDED
        and source.source_quality.value == "primary"
        for source in bundle.sources
    ):
        issues.append(
            _issue(
                IssueLevel.ERROR,
                "WEB_PRIMARY_AUTHORITY_MISSING",
                "sources",
                "Web research retained no successful primary authority; status and "
                "obligations must not be treated as verified.",
            )
        )

    for gap_index, gap in enumerate(bundle.gaps):
        for source_id in gap.source_ids:
            if source_id in source_by_id:
                continue
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "GAP_SOURCE_MISSING",
                    f"gaps[{gap_index}].source_ids",
                    "Gap references a source that is not in the bundle.",
                    gap.gap_id,
                    source_id,
                )
            )

    for finding_index, finding in enumerate(bundle.findings):
        if finding.issue_id not in issue_ids:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "FINDING_ISSUE_MISSING",
                    f"findings[{finding_index}].issue_id",
                    "Finding references an issue that is not in the bundle.",
                    finding.finding_id,
                    finding.issue_id,
                )
            )

    for source_index, source_record in enumerate(bundle.sources):
        path = f"sources[{source_index}]"
        if source_record.fetch_status is FetchStatus.SUCCEEDED:
            actual_hash = sha256_digest(source_record.normalized_text.encode("utf-8"))
            if source_record.content_hash != actual_hash:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "SOURCE_HASH_MISMATCH",
                        f"{path}.content_hash",
                        "Stored source hash does not match normalized text.",
                        source_record.source_id,
                    )
                )
            for field, code, message in (
                (
                    source_record.canonical_url,
                    "SOURCE_CANONICAL_URL_MISSING",
                    "Successful source has no canonical public source URL.",
                ),
                (
                    source_record.publisher,
                    "SOURCE_PUBLISHER_MISSING",
                    "Successful source has no identified publisher.",
                ),
                (
                    source_record.jurisdiction,
                    "SOURCE_JURISDICTION_MISSING",
                    "Successful source has no identified jurisdiction.",
                ),
                (
                    source_record.authority_type,
                    "SOURCE_AUTHORITY_TYPE_MISSING",
                    "Successful source has no identified authority type.",
                ),
            ):
                if field is None or not field.strip():
                    issues.append(
                        _issue(
                            IssueLevel.WARNING,
                            code,
                            path,
                            message,
                            source_record.source_id,
                        )
                    )
            if source_record.source_quality.value == "unknown":
                issues.append(
                    _issue(
                        IssueLevel.WARNING,
                        "SOURCE_QUALITY_UNVERIFIED",
                        f"{path}.source_quality",
                        "Successful source has not been classified as primary or secondary.",
                        source_record.source_id,
                    )
                )
        elif not any(source_record.source_id in gap.source_ids for gap in bundle.gaps):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "FAILED_SOURCE_UNACKNOWLEDGED",
                    path,
                    "Failed source retrieval is not represented as an explicit gap.",
                    source_record.source_id,
                )
            )

    for citation_index, citation_span in enumerate(bundle.citations):
        path = f"citations[{citation_index}]"
        cited_source = source_by_id.get(citation_span.source_id)
        if cited_source is None:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "CITATION_SOURCE_MISSING",
                    f"{path}.source_id",
                    "Citation references a source that is not in the bundle.",
                    citation_span.citation_id,
                    citation_span.source_id,
                )
            )
            continue
        if citation_span.end_char > len(cited_source.normalized_text):
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "CITATION_BOUNDS_INVALID",
                    path,
                    "Citation offsets fall outside normalized source text.",
                    citation_span.citation_id,
                    citation_span.source_id,
                )
            )
            continue
        actual_quote = cited_source.normalized_text[
            citation_span.start_char : citation_span.end_char
        ]
        if actual_quote != citation_span.quote:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "QUOTE_MISMATCH",
                    f"{path}.quote",
                    "Citation quote does not equal the normalized source slice.",
                    citation_span.citation_id,
                    citation_span.source_id,
                )
            )
            resolution = resolve_quote(cited_source.normalized_text, citation_span.quote)
            if resolution.whitespace_match:
                issues.append(
                    _issue(
                        IssueLevel.WARNING,
                        "QUOTE_WHITESPACE_ONLY_MATCH",
                        f"{path}.quote",
                        "Quote matches only after whitespace normalization.",
                        citation_span.citation_id,
                    )
                )

    for finding_index, finding in enumerate(bundle.findings):
        for claim_index, claim in enumerate(finding.claims):
            path = f"findings[{finding_index}].claims[{claim_index}]"
            if claim.kind is ClaimKind.SOURCE_SUPPORTED and not claim.citation_ids:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        "MATERIAL_CLAIM_UNCITED",
                        f"{path}.citation_ids",
                        "Source-supported claim has no citation.",
                        claim.claim_id,
                    )
                )
                continue
            claim_citations = []
            for citation_id in claim.citation_ids:
                linked_citation = citation_by_id.get(citation_id)
                if linked_citation is None:
                    issues.append(
                        _issue(
                            IssueLevel.ERROR,
                            "CLAIM_CITATION_MISSING",
                            f"{path}.citation_ids",
                            "Claim references a citation that is not in the bundle.",
                            claim.claim_id,
                            citation_id,
                        )
                    )
                else:
                    claim_citations.append(linked_citation)
            if claim.kind is ClaimKind.SOURCE_SUPPORTED and claim_citations:
                support = check_claim_support(claim, claim_citations, bundle.sources)
                if support.status is SupportStatus.UNSUPPORTED:
                    issues.append(
                        _issue(
                            IssueLevel.WARNING,
                            "CLAIM_SUPPORT_UNSUPPORTED",
                            path,
                            f"Lexical support floor failed: {support.reason}.",
                            claim.claim_id,
                        )
                    )

    supported_categories = {
        category_by_issue_id[finding.issue_id]
        for finding in bundle.findings
        if finding.issue_id in category_by_issue_id
        and any(
            claim.kind is ClaimKind.SOURCE_SUPPORTED and claim.citation_ids
            for claim in finding.claims
        )
    }
    gap_categories = {gap.category for gap in bundle.gaps}
    for category in REQUIRED_ISSUE_CATEGORIES:
        if category in supported_categories or category in gap_categories:
            continue
        issues.append(
            _issue(
                IssueLevel.ERROR,
                "COVERAGE_DIMENSION_MISSING",
                "issues",
                "Required attorney briefing dimension has neither a supported finding "
                "nor a categorized gap.",
                category.value,
            )
        )

    covered = {finding.jurisdiction.casefold() for finding in bundle.findings}
    covered.update(
        gap.jurisdiction.casefold() for gap in bundle.gaps if gap.jurisdiction is not None
    )
    for jurisdiction in bundle.request.jurisdictions:
        if jurisdiction.casefold() not in covered:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    "JURISDICTION_UNCOVERED",
                    "request.jurisdictions",
                    "Requested jurisdiction has neither a finding nor an explicit gap.",
                    jurisdiction,
                )
            )

    issues.sort(key=lambda item: (item.level.value, item.code, item.path, item.related_ids))
    return ValidationReport(
        valid=not any(issue.level is IssueLevel.ERROR for issue in issues),
        issues=issues,
        validated_at=datetime.now(UTC),
    )
