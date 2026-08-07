"""Deterministic evidence-bundle validation."""

from collections import Counter
from datetime import UTC, datetime

from regulatory_harvest.models import (
    ClaimKind,
    FetchStatus,
    IssueLevel,
    ResearchBundle,
    SupportStatus,
    ValidationIssue,
    ValidationReport,
)
from regulatory_harvest.storage import calculate_bundle_hash, sha256_digest

from .citations import resolve_quote
from .support import check_claim_support


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
    elif bundle.bundle_hash != calculate_bundle_hash(bundle):
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
