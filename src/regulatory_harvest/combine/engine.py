"""Resumable, storage-neutral COMBINE orchestration."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from regulatory_harvest import __version__
from regulatory_harvest.analysis import render_audit_markdown, render_markdown
from regulatory_harvest.models import (
    ResearchBundle,
    ResearchRequest,
    RunError,
    RunManifest,
    StageName,
    StageStatus,
)
from regulatory_harvest.providers import ModelProvider, SearchProvider, SourceFetcher
from regulatory_harvest.storage import (
    ArtifactStore,
    FileSystemArtifactStore,
    calculate_bundle_hash,
    canonical_json_bytes,
)

from .fingerprints import combined_configuration_fingerprint, stage_fingerprint
from .stages import (
    STAGE_IMPLEMENTATION_VERSION,
    StageOutcome,
    build_stage,
    collect_stage,
    export_stage,
    inspect_stage,
    map_stage,
    note_stage,
    organize_stage,
)


class CombineError(RuntimeError):
    """Base error for safe orchestration failures."""


class RunAlreadyActiveError(CombineError):
    """Raised when another writer owns the run lock."""


class RequestConflictError(CombineError):
    """Raised when a run identifier is reused for a different request."""


class CorruptRunError(CombineError):
    """Raised when persisted run state cannot be loaded safely."""


class StageExecutionError(CombineError):
    def __init__(self, stage: StageName) -> None:
        super().__init__(f"{stage.value} stage failed; inspect the persisted manifest")
        self.stage = stage


class RunLock(Protocol):
    async def acquire(self, run_id: str, *, clear_stale: bool = False) -> None: ...

    async def release(self, run_id: str) -> None: ...


class FileSystemRunLock:
    """Exclusive, token-owned lock beside filesystem run artifacts."""

    def __init__(self, store: FileSystemArtifactStore) -> None:
        self._store = store
        self._tokens: dict[str, str] = {}

    def _path(self, run_id: str) -> Path:
        return self._store._artifact_path(run_id, ".run.lock")

    async def acquire(self, run_id: str, *, clear_stale: bool = False) -> None:
        path = self._path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        if clear_stale:
            path.unlink(missing_ok=True)
        token = uuid.uuid4().hex
        try:
            with path.open("x", encoding="utf-8") as stream:
                stream.write(token)
        except FileExistsError as error:
            raise RunAlreadyActiveError(f"run {run_id!r} is already active") from error
        self._tokens[run_id] = token

    async def release(self, run_id: str) -> None:
        token = self._tokens.pop(run_id, None)
        if token is None:
            return
        path = self._path(run_id)
        try:
            if path.read_text(encoding="utf-8") == token:
                path.unlink(missing_ok=True)
        except FileNotFoundError:
            return


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class CombineDependencies:
    artifact_store: ArtifactStore
    source_fetcher: SourceFetcher
    run_lock: RunLock
    model_provider: ModelProvider | None = None
    search_provider: SearchProvider | None = None
    model_provider_fingerprint: str | None = None
    search_provider_fingerprint: str | None = None
    source_fetcher_fingerprint: str = "default-source-fetcher-v1"
    clock: Callable[[], datetime] = _utc_now

    def __post_init__(self) -> None:
        if self.model_provider is not None and not self.model_provider_fingerprint:
            raise ValueError("model_provider_fingerprint is required with a model provider")
        if self.search_provider is not None and not self.search_provider_fingerprint:
            raise ValueError("search_provider_fingerprint is required with a search provider")


@dataclass(frozen=True)
class RunResult:
    manifest: RunManifest
    bundle: ResearchBundle


class CombineEngine:
    """Execute, checkpoint, invalidate, and resume the seven COMBINE stages."""

    def __init__(
        self,
        dependencies: CombineDependencies,
        *,
        generator_version: str = __version__,
    ) -> None:
        self.dependencies = dependencies
        self.generator_version = generator_version

    async def run(
        self,
        request: ResearchRequest,
        force_stage: StageName | None = None,
        *,
        clear_stale_lock: bool = False,
    ) -> RunResult:
        run_id = request.request_id
        await self.dependencies.run_lock.acquire(
            run_id, clear_stale=clear_stale_lock
        )
        try:
            return await self._run_locked(request, force_stage=force_stage)
        finally:
            await self.dependencies.run_lock.release(run_id)

    async def _run_locked(
        self,
        request: ResearchRequest,
        *,
        force_stage: StageName | None,
    ) -> RunResult:
        run_id = request.request_id
        store = self.dependencies.artifact_store
        request_bytes = canonical_json_bytes(request)
        prior_request = await store.read(run_id, "request.json")

        if prior_request is not None and prior_request != request_bytes:
            if force_stage is not StageName.COLLECT:
                raise RequestConflictError(
                    "run identifier belongs to a different research request"
                )
            prior_request = None

        if prior_request is None:
            await store.write_atomic(run_id, "request.json", request_bytes)
            now = self.dependencies.clock()
            manifest = RunManifest(
                run_id=run_id,
                generator_version=self.generator_version,
                created_at=now,
                updated_at=now,
                configuration_fingerprint=self._configuration_fingerprint(),
            )
            await self._write_manifest(manifest)
        else:
            manifest = await self._load_manifest(run_id)

        start_index = await self._first_stage_to_run(
            run_id, manifest, force_stage=force_stage
        )
        if start_index is None:
            bundle = await self._load_bundle(run_id, "bundle.json")
            return RunResult(manifest=manifest, bundle=bundle)

        self._invalidate_from(manifest, start_index)
        await self._write_manifest(manifest)
        if start_index == 0:
            bundle = ResearchBundle(
                generator_version=self.generator_version,
                request=request,
                manifest=manifest,
            )
        else:
            previous = list(StageName)[start_index - 1]
            bundle = await self._load_bundle(
                run_id, self._checkpoint_name(previous)
            )
            bundle.manifest = manifest

        for stage in list(StageName)[start_index:]:
            fingerprint = await self._expected_fingerprint(run_id, stage)
            if fingerprint is None:
                raise CorruptRunError(f"upstream artifact for {stage.value} is missing")
            record = manifest.stage(stage)
            record.status = StageStatus.RUNNING
            record.input_fingerprint = fingerprint
            record.started_at = self.dependencies.clock()
            record.completed_at = None
            record.error = None
            manifest.updated_at = self.dependencies.clock()
            bundle.manifest = manifest
            await self._write_manifest(manifest)

            try:
                outcome = await self._execute(stage, bundle)
            except Exception as error:
                record.status = StageStatus.FAILED
                record.completed_at = self.dependencies.clock()
                record.error = RunError(
                    stage=stage,
                    category=type(error).__name__,
                    retryable=False,
                    message=f"{stage.value} stage failed",
                )
                manifest.updated_at = self.dependencies.clock()
                await self._write_manifest(manifest)
                raise StageExecutionError(stage) from error

            bundle = outcome.bundle
            bundle.manifest = manifest
            checkpoint = self._checkpoint_name(stage)
            await store.write_atomic(run_id, checkpoint, canonical_json_bytes(bundle))
            record.status = outcome.status
            record.completed_at = self.dependencies.clock()
            manifest.updated_at = self.dependencies.clock()
            bundle.manifest = manifest
            await self._write_manifest(manifest)
            await store.write_atomic(run_id, checkpoint, canonical_json_bytes(bundle))

            if stage is StageName.EXPORT:
                await self._write_exports(bundle)

        return RunResult(manifest=manifest, bundle=bundle)

    async def _execute(
        self, stage: StageName, bundle: ResearchBundle
    ) -> StageOutcome:
        if stage is StageName.COLLECT:
            return await collect_stage(
                bundle,
                source_fetcher=self.dependencies.source_fetcher,
                search_provider=self.dependencies.search_provider,
            )
        if stage is StageName.ORGANIZE:
            return organize_stage(bundle)
        if stage is StageName.MAP:
            return await map_stage(
                bundle, model_provider=self.dependencies.model_provider
            )
        if stage is StageName.BUILD:
            return await build_stage(
                bundle, model_provider=self.dependencies.model_provider
            )
        if stage is StageName.INSPECT:
            return inspect_stage(bundle)
        if stage is StageName.NOTE:
            return note_stage(bundle)
        return export_stage(bundle)

    async def _first_stage_to_run(
        self,
        run_id: str,
        manifest: RunManifest,
        *,
        force_stage: StageName | None,
    ) -> int | None:
        stages = list(StageName)
        if force_stage is not None:
            return stages.index(force_stage)
        for index, stage in enumerate(stages):
            record = manifest.stage(stage)
            expected = await self._expected_fingerprint(run_id, stage)
            checkpoint = await self.dependencies.artifact_store.read(
                run_id, self._checkpoint_name(stage)
            )
            status_reusable = record.status is StageStatus.COMPLETED or (
                record.status is StageStatus.SKIPPED
                and stage in {StageName.MAP, StageName.BUILD}
                and self.dependencies.model_provider is None
            )
            if (
                expected is None
                or checkpoint is None
                or not status_reusable
                or record.input_fingerprint != expected
            ):
                return index
            try:
                ResearchBundle.model_validate_json(checkpoint)
            except ValueError:
                return index
        return None

    async def _expected_fingerprint(
        self, run_id: str, stage: StageName
    ) -> str | None:
        stages = list(StageName)
        index = stages.index(stage)
        upstream_name = (
            "request.json"
            if index == 0
            else self._checkpoint_name(stages[index - 1])
        )
        upstream = await self.dependencies.artifact_store.read(run_id, upstream_name)
        if upstream is None:
            return None
        return stage_fingerprint(
            stage,
            upstream,
            implementation_version=STAGE_IMPLEMENTATION_VERSION,
            configuration_fingerprint=self._stage_configuration(stage),
        )

    def _stage_configuration(self, stage: StageName) -> str:
        if stage is StageName.COLLECT:
            return combined_configuration_fingerprint(
                {
                    "search_provider": self.dependencies.search_provider_fingerprint
                    or "none",
                    "source_fetcher": self.dependencies.source_fetcher_fingerprint,
                }
            )
        if stage in {StageName.MAP, StageName.BUILD}:
            return self.dependencies.model_provider_fingerprint or "none"
        return "core"

    def _configuration_fingerprint(self) -> str:
        return combined_configuration_fingerprint(
            {
                "model_provider": self.dependencies.model_provider_fingerprint or "none",
                "search_provider": self.dependencies.search_provider_fingerprint or "none",
                "source_fetcher": self.dependencies.source_fetcher_fingerprint,
            }
        )

    def _invalidate_from(self, manifest: RunManifest, start_index: int) -> None:
        for record in manifest.stages[start_index:]:
            record.status = StageStatus.PENDING
            record.input_fingerprint = None
            record.started_at = None
            record.completed_at = None
            record.error = None
        manifest.configuration_fingerprint = self._configuration_fingerprint()
        manifest.updated_at = self.dependencies.clock()

    async def _load_manifest(self, run_id: str) -> RunManifest:
        data = await self.dependencies.artifact_store.read(run_id, "manifest.json")
        if data is None:
            raise CorruptRunError("request exists without a run manifest")
        try:
            return RunManifest.model_validate_json(data)
        except ValueError as error:
            raise CorruptRunError("run manifest is invalid") from error

    async def _load_bundle(self, run_id: str, artifact: str) -> ResearchBundle:
        data = await self.dependencies.artifact_store.read(run_id, artifact)
        if data is None:
            raise CorruptRunError(f"required artifact {artifact!r} is missing")
        try:
            return ResearchBundle.model_validate_json(data)
        except ValueError as error:
            raise CorruptRunError(f"required artifact {artifact!r} is invalid") from error

    async def _write_manifest(self, manifest: RunManifest) -> None:
        await self.dependencies.artifact_store.write_atomic(
            manifest.run_id, "manifest.json", canonical_json_bytes(manifest)
        )

    async def _write_exports(self, bundle: ResearchBundle) -> None:
        store = self.dependencies.artifact_store
        bundle.bundle_hash = calculate_bundle_hash(bundle)
        await store.write_atomic(
            bundle.manifest.run_id, "bundle.json", canonical_json_bytes(bundle)
        )
        report = render_markdown(bundle).encode("utf-8")
        await store.write_atomic(bundle.manifest.run_id, "report.md", report)
        audit = render_audit_markdown(bundle).encode("utf-8")
        await store.write_atomic(bundle.manifest.run_id, "audit.md", audit)

    @staticmethod
    def _checkpoint_name(stage: StageName) -> str:
        return f"checkpoints/{stage.value}.json"
