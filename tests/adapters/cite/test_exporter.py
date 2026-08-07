import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from regulatory_harvest.adapters.cite import CiteCapabilities, CiteMutationReceipt
from regulatory_harvest.adapters.cite.exporter import (
    CiteDocumentTarget,
    CiteExportValidationError,
    build_cite_export_plan,
    export_bundle_to_cite,
)
from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceInput,
    SourceRecord,
    StageName,
    StageRecord,
)
from regulatory_harvest.storage import calculate_bundle_hash, sha256_digest

FIXTURE = Path(__file__).parent / "fixtures" / "export-responses.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
TEXT = "A controller must document material risks."


def _bundle() -> ResearchBundle:
    source = SourceRecord(
        source_id="source-1",
        origin="https://example.test/rule",
        display_name="Example Rule",
        retrieved_at=NOW,
        content_hash=sha256_digest(TEXT.encode()),
        media_type="text/plain",
        normalized_text=TEXT,
    )
    citation = CitationSpan(
        citation_id="citation-1",
        source_id=source.source_id,
        start_char=13,
        end_char=42,
        quote="must document material risks.",
    )
    claim = Claim(
        claim_id="claim-1",
        text="Controllers must document material risks.",
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
    request = ResearchRequest(
        request_id="run-1",
        question="What must controllers document?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="https://example.test/rule")],
    )
    bundle = ResearchBundle(
        generator_version="0.1.0",
        request=request,
        manifest=RunManifest(
            run_id="run-1",
            generator_version="0.1.0",
            created_at=NOW,
            updated_at=NOW,
            stages=[StageRecord(name=name) for name in StageName],
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
    bundle.bundle_hash = calculate_bundle_hash(bundle)
    return bundle


def _capabilities(*, relationships: bool = True) -> CiteCapabilities:
    operations = {"addAnnotation"}
    if relationships:
        operations.add("addRelationship")
    return CiteCapabilities(
        graphql_url="https://cite.example/graphql",
        operations=frozenset(operations),
        can_write_annotations=True,
        can_write_relationships=relationships,
    )


def _targets() -> dict[str, CiteDocumentTarget]:
    return {"source-1": CiteDocumentTarget(document_id="document-node-1", page=0)}


def test_export_plan_maps_evidence_and_claim_with_provenance() -> None:
    """Missing provenance or wrong document targets would create untraceable annotations."""
    plan = build_cite_export_plan(
        _bundle(),
        corpus_id="corpus-node-1",
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
        capabilities=_capabilities(),
    )

    assert [(item.kind, item.harvest_id) for item in plan.annotations] == [
        ("citation", "citation-1"),
        ("claim", "claim-1:citation-1"),
    ]
    assert all(item.document_id == "document-node-1" for item in plan.annotations)
    assert plan.annotations[0].annotation_json == {
        "0": {
            "bounds": {},
            "rawText": "must document material risks.",
            "tokensJsons": [],
        }
    }
    assert "citation-1" in plan.annotations[0].long_description
    assert "claim-1" in plan.annotations[1].long_description
    assert plan.relationships[0].source_key == "claim:claim-1:citation-1"
    assert plan.relationships[0].target_key == "citation:citation-1"
    assert plan.skipped == []


def test_export_plan_records_unsupported_relationships_explicitly() -> None:
    """Silently omitting requested finding relationships would overstate export completeness."""
    plan = build_cite_export_plan(
        _bundle(),
        corpus_id="corpus-node-1",
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
        capabilities=_capabilities(relationships=False),
    )

    assert plan.relationships == []
    assert len(plan.skipped) == 1
    assert plan.skipped[0].code == "CITE_RELATIONSHIP_WRITE_UNSUPPORTED"
    assert plan.skipped[0].harvest_id == "claim-1:citation-1"


class _RecordingWriteClient:
    def __init__(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.annotation_ids: list[str] = fixture["annotation_ids"]
        self.relationship_id: str = fixture["relationship_id"]
        self.discovery_calls = 0
        self.annotation_calls = 0
        self.relationship_calls = 0

    async def discover_capabilities(self) -> CiteCapabilities:
        self.discovery_calls += 1
        return _capabilities()

    async def create_annotation(self, **_kwargs: object) -> CiteMutationReceipt:
        remote_id = self.annotation_ids[self.annotation_calls]
        self.annotation_calls += 1
        return CiteMutationReceipt(operation="addAnnotation", remote_id=remote_id)

    async def create_relationship(self, **_kwargs: object) -> CiteMutationReceipt:
        self.relationship_calls += 1
        return CiteMutationReceipt(
            operation="addRelationship",
            remote_id=self.relationship_id,
        )


@pytest.mark.asyncio
async def test_invalid_bundle_is_rejected_before_capability_or_write_calls() -> None:
    """Network writes must never begin when citation integrity is already invalid."""
    client = _RecordingWriteClient()
    invalid = _bundle().model_copy(deep=True)
    invalid.sources[0].content_hash = "0" * 64

    with pytest.raises(CiteExportValidationError, match="SOURCE_HASH_MISMATCH"):
        await export_bundle_to_cite(
            client,  # type: ignore[arg-type]
            "corpus-node-1",
            invalid,
            annotation_label_id="annotation-label-1",
            relationship_label_id="relationship-label-1",
            document_targets=_targets(),
        )

    assert client.discovery_calls == 0
    assert client.annotation_calls == 0
    assert client.relationship_calls == 0


@pytest.mark.asyncio
async def test_previous_receipt_reuses_records_without_duplicate_writes() -> None:
    """Retrying a partial or completed export must not duplicate harvested records."""
    client = _RecordingWriteClient()
    first = await export_bundle_to_cite(
        client,  # type: ignore[arg-type]
        "corpus-node-1",
        _bundle(),
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
    )
    second = await export_bundle_to_cite(
        client,  # type: ignore[arg-type]
        "corpus-node-1",
        _bundle(),
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
        previous_result=first,
    )

    assert client.annotation_calls == 2
    assert client.relationship_calls == 1
    assert [entry.status for entry in first.entries] == ["created", "created", "created"]
    assert [entry.status for entry in second.entries] == ["reused", "reused", "reused"]
    assert [entry.remote_id for entry in second.entries] == [
        "annotation-1",
        "annotation-2",
        "relationship-1",
    ]


@pytest.mark.asyncio
async def test_previous_receipt_from_another_corpus_is_rejected_before_network() -> None:
    """Reusing remote IDs from another corpus could connect unrelated legal records."""
    first_client = _RecordingWriteClient()
    previous = await export_bundle_to_cite(
        first_client,  # type: ignore[arg-type]
        "corpus-node-1",
        _bundle(),
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
    )
    previous = previous.model_copy(update={"corpus_id": "different-corpus"})
    retry_client = _RecordingWriteClient()

    with pytest.raises(ValueError, match="different cite corpus"):
        await export_bundle_to_cite(
            retry_client,  # type: ignore[arg-type]
            "corpus-node-1",
            _bundle(),
            annotation_label_id="annotation-label-1",
            relationship_label_id="relationship-label-1",
            document_targets=_targets(),
            previous_result=previous,
        )

    assert retry_client.discovery_calls == 0


@pytest.mark.asyncio
async def test_changed_claim_with_same_id_is_written_again_not_reused() -> None:
    """An identifier collision must not reuse stale analysis content."""
    first_client = _RecordingWriteClient()
    previous = await export_bundle_to_cite(
        first_client,  # type: ignore[arg-type]
        "corpus-node-1",
        _bundle(),
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
    )
    changed = _bundle()
    changed.findings[0].claims[0].text = "Controllers must keep current risk records."
    changed.bundle_hash = calculate_bundle_hash(changed)
    retry_client = _RecordingWriteClient()

    result = await export_bundle_to_cite(
        retry_client,  # type: ignore[arg-type]
        "corpus-node-1",
        changed,
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
        previous_result=previous,
    )

    assert [entry.status for entry in result.entries] == ["reused", "created", "created"]
    assert retry_client.annotation_calls == 1
    assert retry_client.relationship_calls == 1


class _PartialFailureClient(_RecordingWriteClient):
    async def create_annotation(self, **kwargs: object) -> CiteMutationReceipt:
        if self.annotation_calls == 1:
            self.annotation_calls += 1
            raise RuntimeError("sensitive remote failure body")
        return await super().create_annotation(**kwargs)


@pytest.mark.asyncio
async def test_partial_failure_receipt_is_complete_and_retryable() -> None:
    """One failed write must not erase successful remote IDs or leak remote details."""
    result = await export_bundle_to_cite(
        _PartialFailureClient(),  # type: ignore[arg-type]
        "corpus-node-1",
        _bundle(),
        annotation_label_id="annotation-label-1",
        relationship_label_id="relationship-label-1",
        document_targets=_targets(),
    )

    assert [entry.status for entry in result.entries] == ["created", "failed", "skipped"]
    assert result.entries[0].remote_id == "annotation-1"
    assert result.entries[1].error_code == "CITE_WRITE_FAILED"
    assert "sensitive" not in result.model_dump_json()
    assert result.entries[2].error_code == "CITE_DEPENDENCY_UNAVAILABLE"
