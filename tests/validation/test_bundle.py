from datetime import UTC, date, datetime

import pytest

from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    FetchStatus,
    Finding,
    Gap,
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
from regulatory_harvest.storage import calculate_bundle_hash, sha256_digest
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
            )
        ],
        findings=[finding],
        citations=[citation],
    )


def _codes(bundle: ResearchBundle) -> set[str]:
    return {issue.code for issue in validate_bundle(bundle).issues}


def test_valid_bundle_passes_deterministic_validation() -> None:
    """A correct evidence graph must remain a usable export."""
    report = validate_bundle(_bundle())
    assert report.valid is True
    assert not {issue.code for issue in report.issues if issue.level == "error"}


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


def test_validation_issues_have_stable_sort_order() -> None:
    """Filesystem or set iteration order would make reports non-reproducible."""
    bundle = _bundle()
    bundle.request.jurisdictions.extend(["GB", "CA"])
    report = validate_bundle(bundle)
    keys = [(issue.level.value, issue.code, issue.path) for issue in report.issues]
    assert keys == sorted(keys)
