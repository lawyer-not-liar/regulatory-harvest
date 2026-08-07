from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    ResearchBundle,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceInput,
    SourceRecord,
    StageName,
    StageRecord,
    StageStatus,
)


def _now() -> datetime:
    return datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _request() -> ResearchRequest:
    return ResearchRequest(
        request_id="demo",
        question="What does the example rule require?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="example-rule.txt")],
    )


def _bundle() -> ResearchBundle:
    source = SourceRecord(
        source_id="src_example",
        origin="example-rule.txt",
        display_name="Example Rule",
        retrieved_at=_now(),
        content_hash="a" * 64,
        media_type="text/plain",
        normalized_text="A controller must document risks.",
    )
    citation = CitationSpan(
        citation_id="cite-1",
        source_id=source.source_id,
        start_char=13,
        end_char=32,
        quote="must document risks",
    )
    claim = Claim(
        claim_id="claim-1",
        text="The rule requires risk documentation.",
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
        practical_implication="Maintain written risk documentation.",
        claims=[claim],
    )
    manifest = RunManifest(
        run_id="demo",
        generator_version="0.1.0",
        created_at=_now(),
        updated_at=_now(),
        stages=[
            StageRecord(name=name, status=StageStatus.PENDING)
            for name in StageName
        ],
    )
    return ResearchBundle(
        generator_version="0.1.0",
        request=_request(),
        manifest=manifest,
        sources=[source],
        citations=[citation],
        findings=[finding],
    )


def test_request_rejects_empty_jurisdictions() -> None:
    """Removing the non-empty jurisdiction guard would make this test fail."""
    with pytest.raises(ValidationError):
        ResearchRequest(
            request_id="demo",
            question="What does the rule require?",
            jurisdictions=[],
            as_of=date(2026, 8, 5),
            source_inputs=[SourceInput(location="rule.txt")],
        )


@pytest.mark.parametrize("field", ["request_id", "question"])
def test_request_rejects_blank_required_text(field: str) -> None:
    """Removing whitespace stripping from required text would make this test fail."""
    values = _request().model_dump()
    values[field] = "   "
    with pytest.raises(ValidationError):
        ResearchRequest.model_validate(values)


def test_source_input_rejects_blank_location() -> None:
    """Allowing an unusable source location would make this test fail."""
    with pytest.raises(ValidationError):
        SourceInput(location="\t")


def test_citation_uses_half_open_offsets() -> None:
    """Changing offset semantics from half-open would make this arithmetic fail."""
    citation = CitationSpan(
        citation_id="cite-1",
        source_id="source-1",
        start_char=4,
        end_char=8,
        quote="must",
    )
    assert citation.end_char - citation.start_char == len(citation.quote)


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 4), (4, 4), (5, 4)],
)
def test_citation_rejects_invalid_offsets(start: int, end: int) -> None:
    """Dropping offset bounds validation would make this test fail."""
    with pytest.raises(ValidationError):
        CitationSpan(
            citation_id="cite-1",
            source_id="source-1",
            start_char=start,
            end_char=end,
            quote="must",
        )


def test_bundle_round_trip_is_lossless() -> None:
    """Breaking the public JSON contract would make this test fail."""
    bundle = _bundle()
    restored = ResearchBundle.model_validate_json(bundle.model_dump_json())
    assert restored == bundle


def test_bundle_rejects_disabling_attorney_review() -> None:
    """Allowing version 1 bundles to suppress review would make this test fail."""
    values = _bundle().model_dump()
    values["requires_attorney_review"] = False
    with pytest.raises(ValidationError):
        ResearchBundle.model_validate(values)


def test_public_models_reject_unknown_fields() -> None:
    """Relaxing strict schema handling would make this test fail."""
    values = _request().model_dump()
    values["unexpected"] = "silent drift"
    with pytest.raises(ValidationError):
        ResearchRequest.model_validate(values)


def test_manifest_looks_up_each_combine_stage() -> None:
    """Breaking stage addressing would make resume logic fail this test."""
    manifest = _bundle().manifest
    assert manifest.stage(StageName.COLLECT).status is StageStatus.PENDING
    assert [stage.name for stage in manifest.stages] == list(StageName)


def test_manifest_rejects_completed_stage_after_unfinished_stage() -> None:
    """Accepting impossible stage histories would make resume state untrustworthy."""
    stages = [StageRecord(name=name) for name in StageName]
    stages[1].status = StageStatus.COMPLETED

    with pytest.raises(ValidationError, match="terminal stage statuses must form a prefix"):
        RunManifest(
            run_id="demo",
            generator_version="0.1.0",
            created_at=_now(),
            updated_at=_now(),
            stages=stages,
        )
