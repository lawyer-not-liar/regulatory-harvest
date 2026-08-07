"""Deterministic, retryable export plans for cite annotations and relationships."""

from __future__ import annotations

import asyncio
from typing import Literal, Protocol

from pydantic import Field

from regulatory_harvest.models import ResearchBundle
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest
from regulatory_harvest.validation import validate_bundle

from .client import CiteCompatibilityError, CiteError
from .models import CiteCapabilities, CiteMutationReceipt


class CiteExportValidationError(CiteError):
    """A bundle failed deterministic validation before any remote access."""


class CiteDocumentTarget(StrictModel):
    document_id: str
    page: int = Field(default=0, ge=0)


class CitePlannedAnnotation(StrictModel):
    idempotency_key: str
    kind: Literal["citation", "claim"]
    harvest_id: str
    document_id: str
    page: int
    raw_text: str
    annotation_json: dict[str, object]
    long_description: str
    fingerprint: str


class CitePlannedRelationship(StrictModel):
    idempotency_key: str
    harvest_id: str
    document_id: str
    source_key: str
    target_key: str
    fingerprint: str


class CiteSkippedPlanItem(StrictModel):
    idempotency_key: str
    harvest_id: str
    code: str
    message: str


class CiteExportPlan(StrictModel):
    corpus_id: str
    annotation_label_id: str
    relationship_label_id: str | None = None
    annotations: list[CitePlannedAnnotation] = Field(default_factory=list)
    relationships: list[CitePlannedRelationship] = Field(default_factory=list)
    skipped: list[CiteSkippedPlanItem] = Field(default_factory=list)


class CiteExportEntry(StrictModel):
    idempotency_key: str
    operation: Literal["annotation", "relationship", "plan"]
    harvest_id: str
    status: Literal["created", "reused", "skipped", "failed"]
    remote_id: str | None = None
    error_code: str | None = None
    fingerprint: str | None = None


class CiteExportResult(StrictModel):
    corpus_id: str
    entries: list[CiteExportEntry] = Field(default_factory=list)


class CiteWriteClient(Protocol):
    async def discover_capabilities(self) -> CiteCapabilities: ...

    async def create_annotation(
        self,
        *,
        corpus_id: str,
        document_id: str,
        annotation_label_id: str,
        raw_text: str,
        page: int,
        annotation_json: dict[str, object],
        long_description: str | None = None,
        annotation_type: str = "TOKEN_LABEL",
    ) -> CiteMutationReceipt: ...

    async def create_relationship(
        self,
        *,
        corpus_id: str,
        document_id: str,
        relationship_label_id: str,
        source_ids: list[str],
        target_ids: list[str],
    ) -> CiteMutationReceipt: ...


def _ensure_valid(bundle: ResearchBundle) -> None:
    report = validate_bundle(bundle, require_bundle_hash=True)
    if not report.valid:
        codes = sorted({issue.code for issue in report.issues if issue.level.value == "error"})
        raise CiteExportValidationError(
            f"bundle is not exportable: {', '.join(codes) or 'validation failed'}"
        )


def _selection_json(page: int, quote: str) -> dict[str, object]:
    return {
        str(page): {
            "bounds": {},
            "rawText": quote,
            "tokensJsons": [],
        }
    }


def _fingerprint(value: object) -> str:
    return sha256_digest(canonical_json_bytes(value))


def _planned_annotation(
    *,
    key: str,
    kind: Literal["citation", "claim"],
    harvest_id: str,
    document_id: str,
    page: int,
    raw_text: str,
    long_description: str,
) -> CitePlannedAnnotation:
    annotation_json = _selection_json(page, raw_text)
    payload = {
        "annotation_json": annotation_json,
        "document_id": document_id,
        "harvest_id": harvest_id,
        "kind": kind,
        "long_description": long_description,
        "page": page,
        "raw_text": raw_text,
    }
    return CitePlannedAnnotation(
        idempotency_key=key,
        kind=kind,
        harvest_id=harvest_id,
        document_id=document_id,
        page=page,
        raw_text=raw_text,
        annotation_json=annotation_json,
        long_description=long_description,
        fingerprint=_fingerprint(payload),
    )


def _citation_description(bundle: ResearchBundle, citation_id: str, source_id: str) -> str:
    return (
        "Regulatory Harvest provenance: "
        f"kind=citation; run_id={bundle.manifest.run_id}; "
        f"harvest_id={citation_id}; source_id={source_id}"
    )


def _claim_description(
    bundle: ResearchBundle,
    finding_id: str,
    claim_id: str,
    citation_id: str,
    claim_text: str,
) -> str:
    return (
        "Regulatory Harvest provenance: "
        f"kind=claim; run_id={bundle.manifest.run_id}; "
        f"harvest_id={claim_id}:{citation_id}; finding_id={finding_id}; "
        f"citation_id={citation_id}\n\nClaim: {claim_text}"
    )


def build_cite_export_plan(
    bundle: ResearchBundle,
    *,
    corpus_id: str,
    annotation_label_id: str,
    relationship_label_id: str | None,
    document_targets: dict[str, CiteDocumentTarget],
    capabilities: CiteCapabilities,
) -> CiteExportPlan:
    """Build a pure, stable plan after validating all evidence references."""
    _ensure_valid(bundle)
    if bundle.citations and not capabilities.can_write_annotations:
        raise CiteCompatibilityError(
            "cite target does not advertise required operation addAnnotation"
        )

    citations_by_id = {citation.citation_id: citation for citation in bundle.citations}
    annotations: list[CitePlannedAnnotation] = []
    relationships: list[CitePlannedRelationship] = []
    skipped: list[CiteSkippedPlanItem] = []
    planned_citation_keys: set[str] = set()

    for citation in bundle.citations:
        target = document_targets.get(citation.source_id)
        key = f"citation:{citation.citation_id}"
        if target is None:
            skipped.append(
                CiteSkippedPlanItem(
                    idempotency_key=key,
                    harvest_id=citation.citation_id,
                    code="CITE_DOCUMENT_TARGET_MISSING",
                    message="No cite document node ID was supplied for the citation source.",
                )
            )
            continue
        annotations.append(
            _planned_annotation(
                key=key,
                kind="citation",
                harvest_id=citation.citation_id,
                document_id=target.document_id,
                page=target.page,
                raw_text=citation.quote,
                long_description=_citation_description(
                    bundle, citation.citation_id, citation.source_id
                ),
            )
        )
        planned_citation_keys.add(key)

    for finding in bundle.findings:
        for claim in finding.claims:
            for citation_id in claim.citation_ids:
                linked_citation = citations_by_id.get(citation_id)
                if linked_citation is None:
                    continue
                target = document_targets.get(linked_citation.source_id)
                harvest_id = f"{claim.claim_id}:{citation_id}"
                claim_key = f"claim:{harvest_id}"
                citation_key = f"citation:{citation_id}"
                if target is None or citation_key not in planned_citation_keys:
                    skipped.append(
                        CiteSkippedPlanItem(
                            idempotency_key=claim_key,
                            harvest_id=harvest_id,
                            code="CITE_DOCUMENT_TARGET_MISSING",
                            message="No cite document node ID was supplied for the claim source.",
                        )
                    )
                    continue
                claim_annotation = _planned_annotation(
                    key=claim_key,
                    kind="claim",
                    harvest_id=harvest_id,
                    document_id=target.document_id,
                    page=target.page,
                    raw_text=linked_citation.quote,
                    long_description=_claim_description(
                        bundle,
                        finding.finding_id,
                        claim.claim_id,
                        citation_id,
                        claim.text,
                    ),
                )
                annotations.append(claim_annotation)
                relationship_key = f"relationship:{harvest_id}"
                if relationship_label_id is None:
                    continue
                if capabilities.can_write_relationships:
                    citation_fingerprint = next(
                        item.fingerprint
                        for item in annotations
                        if item.idempotency_key == citation_key
                    )
                    relationships.append(
                        CitePlannedRelationship(
                            idempotency_key=relationship_key,
                            harvest_id=harvest_id,
                            document_id=target.document_id,
                            source_key=claim_key,
                            target_key=citation_key,
                            fingerprint=_fingerprint(
                                {
                                    "document_id": target.document_id,
                                    "harvest_id": harvest_id,
                                    "relationship_label_id": relationship_label_id,
                                    "source_fingerprint": claim_annotation.fingerprint,
                                    "target_fingerprint": citation_fingerprint,
                                }
                            ),
                        )
                    )
                else:
                    skipped.append(
                        CiteSkippedPlanItem(
                            idempotency_key=relationship_key,
                            harvest_id=harvest_id,
                            code="CITE_RELATIONSHIP_WRITE_UNSUPPORTED",
                            message="cite target does not advertise addRelationship.",
                        )
                    )

    return CiteExportPlan(
        corpus_id=corpus_id,
        annotation_label_id=annotation_label_id,
        relationship_label_id=relationship_label_id,
        annotations=annotations,
        relationships=relationships,
        skipped=skipped,
    )


def _reusable_entries(previous: CiteExportResult | None) -> dict[str, CiteExportEntry]:
    if previous is None:
        return {}
    return {
        entry.idempotency_key: entry
        for entry in previous.entries
        if entry.remote_id is not None and entry.status in {"created", "reused"}
    }


async def export_bundle_to_cite(
    client: CiteWriteClient,
    corpus_id: str,
    bundle: ResearchBundle,
    *,
    annotation_label_id: str,
    relationship_label_id: str | None,
    document_targets: dict[str, CiteDocumentTarget],
    previous_result: CiteExportResult | None = None,
    concurrency: int = 1,
) -> CiteExportResult:
    """Validate, plan, and execute bounded writes with a retryable receipt."""
    _ensure_valid(bundle)
    if concurrency < 1 or concurrency > 5:
        raise ValueError("concurrency must be between 1 and 5")
    if previous_result is not None and previous_result.corpus_id != corpus_id:
        raise ValueError("previous export receipt belongs to a different cite corpus")
    capabilities = await client.discover_capabilities()
    plan = build_cite_export_plan(
        bundle,
        corpus_id=corpus_id,
        annotation_label_id=annotation_label_id,
        relationship_label_id=relationship_label_id,
        document_targets=document_targets,
        capabilities=capabilities,
    )
    reusable = _reusable_entries(previous_result)
    semaphore = asyncio.Semaphore(concurrency)

    async def execute_annotation(item: CitePlannedAnnotation) -> CiteExportEntry:
        prior = reusable.get(item.idempotency_key)
        if prior is not None and prior.fingerprint == item.fingerprint:
            return prior.model_copy(update={"status": "reused"})
        try:
            async with semaphore:
                receipt = await client.create_annotation(
                    corpus_id=plan.corpus_id,
                    document_id=item.document_id,
                    annotation_label_id=plan.annotation_label_id,
                    raw_text=item.raw_text,
                    page=item.page,
                    annotation_json=item.annotation_json,
                    long_description=item.long_description,
                )
            return CiteExportEntry(
                idempotency_key=item.idempotency_key,
                operation="annotation",
                harvest_id=item.harvest_id,
                status="created",
                remote_id=receipt.remote_id,
                fingerprint=item.fingerprint,
            )
        except Exception:
            return CiteExportEntry(
                idempotency_key=item.idempotency_key,
                operation="annotation",
                harvest_id=item.harvest_id,
                status="failed",
                error_code="CITE_WRITE_FAILED",
                fingerprint=item.fingerprint,
            )

    annotation_entries = list(
        await asyncio.gather(*(execute_annotation(item) for item in plan.annotations))
    )
    remote_ids = {
        entry.idempotency_key: entry.remote_id
        for entry in annotation_entries
        if entry.remote_id is not None
    }

    async def execute_relationship(item: CitePlannedRelationship) -> CiteExportEntry:
        prior = reusable.get(item.idempotency_key)
        if prior is not None and prior.fingerprint == item.fingerprint:
            return prior.model_copy(update={"status": "reused"})
        source_id = remote_ids.get(item.source_key)
        target_id = remote_ids.get(item.target_key)
        if source_id is None or target_id is None or plan.relationship_label_id is None:
            return CiteExportEntry(
                idempotency_key=item.idempotency_key,
                operation="relationship",
                harvest_id=item.harvest_id,
                status="skipped",
                error_code="CITE_DEPENDENCY_UNAVAILABLE",
                fingerprint=item.fingerprint,
            )
        try:
            async with semaphore:
                receipt = await client.create_relationship(
                    corpus_id=plan.corpus_id,
                    document_id=item.document_id,
                    relationship_label_id=plan.relationship_label_id,
                    source_ids=[source_id],
                    target_ids=[target_id],
                )
            return CiteExportEntry(
                idempotency_key=item.idempotency_key,
                operation="relationship",
                harvest_id=item.harvest_id,
                status="created",
                remote_id=receipt.remote_id,
                fingerprint=item.fingerprint,
            )
        except Exception:
            return CiteExportEntry(
                idempotency_key=item.idempotency_key,
                operation="relationship",
                harvest_id=item.harvest_id,
                status="failed",
                error_code="CITE_WRITE_FAILED",
                fingerprint=item.fingerprint,
            )

    relationship_entries = list(
        await asyncio.gather(*(execute_relationship(item) for item in plan.relationships))
    )
    skipped_entries = [
        CiteExportEntry(
            idempotency_key=item.idempotency_key,
            operation="plan",
            harvest_id=item.harvest_id,
            status="skipped",
            error_code=item.code,
        )
        for item in plan.skipped
    ]
    return CiteExportResult(
        corpus_id=corpus_id,
        entries=annotation_entries + relationship_entries + skipped_entries,
    )
