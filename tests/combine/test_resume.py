import pytest

from regulatory_harvest.combine import (
    CombineDependencies,
    CombineEngine,
    FileSystemRunLock,
    RequestConflictError,
    StageExecutionError,
)
from regulatory_harvest.models import ResearchBundle, RunManifest, StageName, StageStatus
from regulatory_harvest.storage import FileSystemArtifactStore

from .support import CountingFetcher, RecordingProvider, TickingClock, request


def _engine(store, fetcher, *, provider=None) -> CombineEngine:
    return CombineEngine(
        CombineDependencies(
            artifact_store=store,
            source_fetcher=fetcher,
            model_provider=provider,
            model_provider_fingerprint="fake-v1" if provider is not None else None,
            run_lock=FileSystemRunLock(store),
            clock=TickingClock(),
        )
    )


@pytest.mark.asyncio
async def test_resume_does_not_repeat_completed_collect(tmp_path) -> None:
    """Ignoring the checkpoint would fetch the same explicit sources twice."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    engine = _engine(store, fetcher)

    first = await engine.run(request())
    second = await engine.run(request())

    assert len(fetcher.calls) == 1
    assert second.bundle == first.bundle


@pytest.mark.asyncio
async def test_force_organize_repairs_it_without_repeating_collect(tmp_path) -> None:
    """Invalidating too much would refetch; too little would retain corruption."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    engine = _engine(store, fetcher)
    await engine.run(request())
    collect_before = await store.read("run-1", "checkpoints/collect.json")
    await store.write_atomic("run-1", "checkpoints/organize.json", b"not-json")

    result = await engine.run(request(), force_stage=StageName.ORGANIZE)

    assert len(fetcher.calls) == 1
    assert await store.read("run-1", "checkpoints/collect.json") == collect_before
    repaired = await store.read("run-1", "checkpoints/organize.json")
    assert repaired is not None
    assert ResearchBundle.model_validate_json(repaired).sources == result.bundle.sources


@pytest.mark.asyncio
async def test_interrupted_build_resumes_from_failed_stage(tmp_path) -> None:
    """Restarting from Collect would waste retrieval and discard usable checkpoints."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    provider = RecordingProvider(fail_first_build=True)
    engine = _engine(store, fetcher, provider=provider)

    with pytest.raises(StageExecutionError):
        await engine.run(request())

    manifest_data = await store.read("run-1", "manifest.json")
    assert manifest_data is not None
    interrupted = RunManifest.model_validate_json(manifest_data)
    assert interrupted.stage(StageName.COLLECT).status is StageStatus.COMPLETED
    assert interrupted.stage(StageName.ORGANIZE).status is StageStatus.COMPLETED
    assert interrupted.stage(StageName.MAP).status is StageStatus.COMPLETED
    assert interrupted.stage(StageName.BUILD).status is StageStatus.FAILED
    assert await store.read("run-1", "checkpoints/map.json") is not None

    resumed = await engine.run(request())

    assert len(fetcher.calls) == 1
    assert provider.map_calls == 1
    assert provider.build_calls == 2
    assert resumed.manifest.stage(StageName.BUILD).status is StageStatus.COMPLETED
    assert resumed.bundle.validation is not None
    assert resumed.bundle.validation.valid is True


@pytest.mark.asyncio
async def test_reusing_run_id_with_different_request_is_rejected(tmp_path) -> None:
    """Loading checkpoints for a different legal question would mix provenance."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    engine = _engine(store, CountingFetcher())
    await engine.run(request())

    with pytest.raises(RequestConflictError):
        await engine.run(request(question="What records must a processor retain?"))


@pytest.mark.asyncio
async def test_adding_model_provider_resumes_at_map(tmp_path) -> None:
    """A newly available model should not force explicit source retrieval to repeat."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    offline = _engine(store, fetcher)
    offline_result = await offline.run(request())
    collect_before = await store.read("run-1", "checkpoints/collect.json")
    provider = RecordingProvider()

    configured_result = await _engine(store, fetcher, provider=provider).run(request())

    assert len(fetcher.calls) == 1
    assert await store.read("run-1", "checkpoints/collect.json") == collect_before
    assert offline_result.manifest.stage(StageName.MAP).status is StageStatus.SKIPPED
    assert configured_result.manifest.stage(StageName.MAP).status is StageStatus.COMPLETED
    assert provider.map_calls == 1
    assert provider.build_calls == 1


@pytest.mark.asyncio
async def test_changed_model_fingerprint_invalidates_map_and_build_only(tmp_path) -> None:
    """Reusing model output across configuration changes would hide stale analysis."""
    store = FileSystemArtifactStore(tmp_path / "runs")
    fetcher = CountingFetcher()
    provider = RecordingProvider()
    first = CombineEngine(
        CombineDependencies(
            artifact_store=store,
            source_fetcher=fetcher,
            model_provider=provider,
            model_provider_fingerprint="model-config-v1",
            run_lock=FileSystemRunLock(store),
            clock=TickingClock(),
        )
    )
    await first.run(request())

    second = CombineEngine(
        CombineDependencies(
            artifact_store=store,
            source_fetcher=fetcher,
            model_provider=provider,
            model_provider_fingerprint="model-config-v2",
            run_lock=FileSystemRunLock(store),
            clock=TickingClock(),
        )
    )
    await second.run(request())

    assert len(fetcher.calls) == 1
    assert provider.map_calls == 2
    assert provider.build_calls == 2
