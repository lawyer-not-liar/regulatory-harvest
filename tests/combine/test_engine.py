import asyncio

import pytest

from regulatory_harvest.combine import (
    CombineDependencies,
    CombineEngine,
    FileSystemRunLock,
    RunAlreadyActiveError,
)
from regulatory_harvest.models import DISCLAIMER, ResearchBundle, StageName, StageStatus
from regulatory_harvest.storage import FileSystemArtifactStore, calculate_bundle_hash

from .support import BlockingFetcher, CountingFetcher, TickingClock, request


@pytest.mark.asyncio
async def test_offline_run_completes_with_visible_analysis_gap(tmp_path) -> None:
    """Silently pretending to analyze without a model would make this fail."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    engine = CombineEngine(
        CombineDependencies(
            artifact_store=store,
            source_fetcher=fetcher,
            run_lock=FileSystemRunLock(store),
            clock=TickingClock(),
        )
    )

    result = await engine.run(request())

    assert result.manifest.stage(StageName.COLLECT).status is StageStatus.COMPLETED
    assert result.manifest.stage(StageName.ORGANIZE).status is StageStatus.COMPLETED
    assert result.manifest.stage(StageName.MAP).status is StageStatus.SKIPPED
    assert result.manifest.stage(StageName.BUILD).status is StageStatus.SKIPPED
    assert result.manifest.stage(StageName.INSPECT).status is StageStatus.COMPLETED
    assert result.manifest.stage(StageName.NOTE).status is StageStatus.COMPLETED
    assert result.manifest.stage(StageName.EXPORT).status is StageStatus.COMPLETED
    assert any(
        gap.code == "MODEL_PROVIDER_NOT_CONFIGURED" and gap.jurisdiction == "US"
        for gap in result.bundle.gaps
    )
    assert result.bundle.validation is not None
    assert result.bundle.validation.valid is True
    assert result.bundle.bundle_hash == calculate_bundle_hash(result.bundle)

    bundle_data = await store.read("run-1", "bundle.json")
    report_data = await store.read("run-1", "report.md")
    assert bundle_data is not None
    assert ResearchBundle.model_validate_json(bundle_data) == result.bundle
    assert report_data is not None
    assert DISCLAIMER in report_data.decode()


@pytest.mark.asyncio
async def test_same_run_is_locked_while_collect_is_active(tmp_path) -> None:
    """Two writers entering the same run would corrupt stage checkpoints."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = BlockingFetcher()
    dependencies = CombineDependencies(
        artifact_store=store,
        source_fetcher=fetcher,
        run_lock=FileSystemRunLock(store),
        clock=TickingClock(),
    )
    first = asyncio.create_task(CombineEngine(dependencies).run(request()))
    await fetcher.started.wait()

    with pytest.raises(RunAlreadyActiveError):
        await CombineEngine(dependencies).run(request())

    fetcher.release.set()
    await first


@pytest.mark.asyncio
async def test_stale_lock_requires_explicit_clear(tmp_path) -> None:
    """Implicitly deleting an existing lock could overwrite an active run."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    stale_lock = FileSystemRunLock(store)
    await stale_lock.acquire("run-1")
    engine = CombineEngine(
        CombineDependencies(
            artifact_store=store,
            source_fetcher=CountingFetcher(),
            run_lock=FileSystemRunLock(store),
            clock=TickingClock(),
        )
    )

    with pytest.raises(RunAlreadyActiveError):
        await engine.run(request())

    result = await engine.run(request(), clear_stale_lock=True)
    assert result.manifest.stage(StageName.EXPORT).status is StageStatus.COMPLETED
