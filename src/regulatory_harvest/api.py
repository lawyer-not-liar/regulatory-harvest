"""Small public Python API for local Regulatory Harvest runs."""

from __future__ import annotations

import asyncio
from pathlib import Path

from regulatory_harvest.analysis import render_audit_markdown, render_markdown
from regulatory_harvest.combine import (
    CombineDependencies,
    CombineEngine,
    FileSystemRunLock,
    RunResult,
)
from regulatory_harvest.models import (
    ResearchBundle,
    ResearchRequest,
    StageName,
    ValidationReport,
)
from regulatory_harvest.providers import ModelProvider, SearchProvider, SourceFetcher
from regulatory_harvest.sources import DefaultSourceFetcher
from regulatory_harvest.storage import FileSystemArtifactStore
from regulatory_harvest.validation import validate_bundle


def _load_request(value: ResearchRequest | Path) -> tuple[ResearchRequest, Path]:
    if isinstance(value, ResearchRequest):
        return value, Path.cwd()
    path = value.expanduser().resolve(strict=True)
    return ResearchRequest.model_validate_json(path.read_bytes()), path.parent


def _load_bundle(value: ResearchBundle | Path) -> ResearchBundle:
    if isinstance(value, ResearchBundle):
        return value
    return ResearchBundle.model_validate_json(value.expanduser().read_bytes())


async def run_research(
    request: ResearchRequest | Path,
    output_dir: Path,
    *,
    source_fetcher: SourceFetcher | None = None,
    source_fetcher_fingerprint: str = "default-source-fetcher-v1",
    model_provider: ModelProvider | None = None,
    model_provider_fingerprint: str | None = None,
    search_provider: SearchProvider | None = None,
    search_provider_fingerprint: str | None = None,
    force_stage: StageName | None = None,
    clear_stale_lock: bool = False,
) -> RunResult:
    """Run COMBINE using a caller-selected filesystem output directory."""
    parsed, base_dir = _load_request(request)
    store = FileSystemArtifactStore(output_dir)
    fetcher = source_fetcher or DefaultSourceFetcher(base_dir=base_dir)
    dependencies = CombineDependencies(
        artifact_store=store,
        source_fetcher=fetcher,
        source_fetcher_fingerprint=source_fetcher_fingerprint,
        model_provider=model_provider,
        model_provider_fingerprint=model_provider_fingerprint,
        search_provider=search_provider,
        search_provider_fingerprint=search_provider_fingerprint,
        run_lock=FileSystemRunLock(store),
    )
    return await CombineEngine(dependencies).run(
        parsed,
        force_stage=force_stage,
        clear_stale_lock=clear_stale_lock,
    )


def run_research_sync(
    request: ResearchRequest | Path,
    output_dir: Path,
    *,
    source_fetcher: SourceFetcher | None = None,
    source_fetcher_fingerprint: str = "default-source-fetcher-v1",
    model_provider: ModelProvider | None = None,
    model_provider_fingerprint: str | None = None,
    search_provider: SearchProvider | None = None,
    search_provider_fingerprint: str | None = None,
    force_stage: StageName | None = None,
    clear_stale_lock: bool = False,
) -> RunResult:
    """Synchronous convenience wrapper that refuses nested event loops."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            run_research(
                request,
                output_dir,
                source_fetcher=source_fetcher,
                source_fetcher_fingerprint=source_fetcher_fingerprint,
                model_provider=model_provider,
                model_provider_fingerprint=model_provider_fingerprint,
                search_provider=search_provider,
                search_provider_fingerprint=search_provider_fingerprint,
                force_stage=force_stage,
                clear_stale_lock=clear_stale_lock,
            )
        )
    raise RuntimeError("run_research_sync cannot run inside an active event loop")


def validate_research_bundle(bundle: ResearchBundle | Path) -> ValidationReport:
    return validate_bundle(_load_bundle(bundle), require_bundle_hash=True)


def render_report(bundle: ResearchBundle | Path) -> str:
    loaded = _load_bundle(bundle)
    report = validate_bundle(loaded, require_bundle_hash=True)
    rendered = loaded.model_copy(deep=True)
    rendered.validation = report
    return render_markdown(rendered)


def render_audit(bundle: ResearchBundle | Path) -> str:
    loaded = _load_bundle(bundle)
    report = validate_bundle(loaded, require_bundle_hash=True)
    rendered = loaded.model_copy(deep=True)
    rendered.validation = report
    return render_audit_markdown(rendered)
