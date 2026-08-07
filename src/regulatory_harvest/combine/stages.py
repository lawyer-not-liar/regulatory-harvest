"""Pure and provider-facing COMBINE stage behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from regulatory_harvest import __version__
from regulatory_harvest.analysis import AnalysisDraft, build_analysis
from regulatory_harvest.models import (
    FetchStatus,
    Gap,
    ResearchBundle,
    ResearchRequest,
    ReviewItem,
    SourceInput,
    SourceRecord,
    StageStatus,
)
from regulatory_harvest.providers import (
    ModelProvider,
    ModelRequest,
    SearchProvider,
    SearchQuery,
    SourceExcerpt,
    SourceFetcher,
)
from regulatory_harvest.storage import sha256_digest
from regulatory_harvest.validation import validate_bundle


@dataclass(frozen=True)
class StageOutcome:
    bundle: ResearchBundle
    status: StageStatus = StageStatus.COMPLETED


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{sha256_digest(chr(0).join(parts).encode())[:24]}"


async def collect_stage(
    bundle: ResearchBundle,
    *,
    source_fetcher: SourceFetcher,
    search_provider: SearchProvider | None,
) -> StageOutcome:
    inputs = list(bundle.request.source_inputs)
    if search_provider is not None:
        results = await search_provider.search(
            SearchQuery(
                query=bundle.request.question,
                jurisdictions=bundle.request.jurisdictions,
                as_of=bundle.request.as_of,
            )
        )
        known_locations = {source.location for source in inputs}
        for result in sorted(results, key=lambda item: item.rank):
            if result.url in known_locations:
                continue
            inputs.append(SourceInput(location=result.url, title=result.title))
            known_locations.add(result.url)

    bundle.sources = [await source_fetcher.fetch(source_input) for source_input in inputs]
    return StageOutcome(bundle=bundle)


def organize_stage(bundle: ResearchBundle) -> StageOutcome:
    """Preserve every origin attempt while stabilizing source order."""
    bundle.sources = sorted(
        bundle.sources,
        key=lambda source: (source.content_hash or "", source.source_id, source.origin),
    )
    return StageOutcome(bundle=bundle)


def _source_excerpts(sources: list[SourceRecord]) -> list[SourceExcerpt]:
    excerpts: list[SourceExcerpt] = []
    seen_hashes: set[str] = set()
    for source in sources:
        if source.fetch_status is not FetchStatus.SUCCEEDED or source.content_hash is None:
            continue
        if source.content_hash in seen_hashes:
            continue
        seen_hashes.add(source.content_hash)
        metadata = {"display_name": source.display_name}
        if source.jurisdiction is not None:
            metadata["jurisdiction"] = source.jurisdiction
        excerpts.append(
            SourceExcerpt(
                source_id=source.source_id,
                text=source.normalized_text,
                metadata=metadata,
            )
        )
    return excerpts


def _model_request(
    operation: Literal["map", "build"],
    request: ResearchRequest,
    sources: list[SourceRecord],
) -> ModelRequest:
    instructions = (
        "Identify the regulatory issues in the supplied sources."
        if operation == "map"
        else "Build evidence-grounded findings and propose exact source quotes."
    )
    return ModelRequest(
        operation=operation,
        instructions_version=f"{operation}-v1",
        system_instructions=instructions,
        json_schema=AnalysisDraft.model_json_schema(),
        source_excerpts=_source_excerpts(sources),
        safe_metadata={
            "as_of": request.as_of.isoformat(),
            "jurisdictions": ", ".join(request.jurisdictions),
            "question": request.question,
        },
    )


async def map_stage(
    bundle: ResearchBundle,
    *,
    model_provider: ModelProvider | None,
) -> StageOutcome:
    if model_provider is None:
        existing = {(gap.code, gap.jurisdiction) for gap in bundle.gaps}
        for jurisdiction in bundle.request.jurisdictions:
            if ("MODEL_PROVIDER_NOT_CONFIGURED", jurisdiction) in existing:
                continue
            bundle.gaps.append(
                Gap(
                    gap_id=_stable_id(
                        "gap", "MODEL_PROVIDER_NOT_CONFIGURED", jurisdiction
                    ),
                    code="MODEL_PROVIDER_NOT_CONFIGURED",
                    message="No model provider was configured; analysis stages were skipped.",
                    jurisdiction=jurisdiction,
                )
            )
        return StageOutcome(bundle=bundle, status=StageStatus.SKIPPED)

    response = await model_provider.complete(
        _model_request("map", bundle.request, bundle.sources)
    )
    bundle.issues = build_analysis(response.parsed, bundle.sources).issues
    bundle.manifest.provider_metadata["model_provider"] = response.provider_name
    bundle.manifest.provider_metadata["model"] = response.model_name
    return StageOutcome(bundle=bundle)


async def build_stage(
    bundle: ResearchBundle,
    *,
    model_provider: ModelProvider | None,
) -> StageOutcome:
    if model_provider is None:
        return StageOutcome(bundle=bundle, status=StageStatus.SKIPPED)

    response = await model_provider.complete(
        _model_request("build", bundle.request, bundle.sources)
    )
    built = build_analysis(response.parsed, bundle.sources)
    bundle.issues = built.issues
    bundle.findings = built.findings
    bundle.citations = built.citations
    bundle.review_items = built.review_items
    bundle.manifest.provider_metadata["model_provider"] = response.provider_name
    bundle.manifest.provider_metadata["model"] = response.model_name
    return StageOutcome(bundle=bundle)


def inspect_stage(bundle: ResearchBundle) -> StageOutcome:
    bundle.validation = validate_bundle(bundle)
    return StageOutcome(bundle=bundle)


def note_stage(bundle: ResearchBundle) -> StageOutcome:
    gap_keys: set[tuple[str, str | None, tuple[str, ...]]] = {
        (gap.code, gap.jurisdiction, tuple(gap.source_ids)) for gap in bundle.gaps
    }
    for source in bundle.sources:
        if source.fetch_status is not FetchStatus.FAILED:
            continue
        source_gap_key = (
            "SOURCE_RETRIEVAL_FAILED",
            source.jurisdiction,
            (source.source_id,),
        )
        if source_gap_key in gap_keys:
            continue
        bundle.gaps.append(
            Gap(
                gap_id=_stable_id("gap", "SOURCE_RETRIEVAL_FAILED", source.source_id),
                code="SOURCE_RETRIEVAL_FAILED",
                message="A requested source could not be retrieved or normalized.",
                jurisdiction=source.jurisdiction,
                source_ids=[source.source_id],
            )
        )
        gap_keys.add(source_gap_key)

    current_validation = bundle.validation or validate_bundle(bundle)
    review_codes = {
        "CITATION_BOUNDS_INVALID",
        "CITATION_SOURCE_MISSING",
        "CLAIM_CITATION_MISSING",
        "CLAIM_SUPPORT_UNSUPPORTED",
        "MATERIAL_CLAIM_UNCITED",
        "QUOTE_MISMATCH",
    }
    existing_reviews = {(item.code, tuple(item.related_ids)) for item in bundle.review_items}
    for issue in current_validation.issues:
        if issue.code == "JURISDICTION_UNCOVERED" and issue.related_ids:
            jurisdiction = issue.related_ids[0]
            jurisdiction_gap_key = ("JURISDICTION_UNCOVERED", jurisdiction, ())
            if jurisdiction_gap_key not in gap_keys:
                bundle.gaps.append(
                    Gap(
                        gap_id=_stable_id("gap", "JURISDICTION_UNCOVERED", jurisdiction),
                        code="JURISDICTION_UNCOVERED",
                        message="No supported finding was produced for this jurisdiction.",
                        jurisdiction=jurisdiction,
                    )
                )
                gap_keys.add(jurisdiction_gap_key)
        if issue.code not in review_codes:
            continue
        review_key = (issue.code, tuple(issue.related_ids))
        if review_key in existing_reviews:
            continue
        bundle.review_items.append(
            ReviewItem(
                review_id=_stable_id(
                    "review", issue.code, issue.path, *issue.related_ids
                ),
                code=issue.code,
                message=issue.message,
                related_ids=issue.related_ids,
                context={"path": issue.path, "level": issue.level.value},
            )
        )
        existing_reviews.add(review_key)

    bundle.validation = validate_bundle(bundle)
    return StageOutcome(bundle=bundle)


def export_stage(bundle: ResearchBundle) -> StageOutcome:
    return StageOutcome(bundle=bundle)


STAGE_IMPLEMENTATION_VERSION = f"{__version__}:combine-v1"
