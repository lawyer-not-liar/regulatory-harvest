import os
from pathlib import Path

import pytest

from regulatory_harvest.storage import FileSystemArtifactStore, UnsafeArtifactPathError


@pytest.mark.asyncio
async def test_write_atomic_persists_bytes_without_temp_residue(tmp_path: Path) -> None:
    """Replacing atomic writes with direct writes would lose this cleanup guarantee."""
    store = FileSystemArtifactStore(tmp_path)
    await store.write_atomic("run-1", "manifest.json", b'{"ok":true}')

    assert await store.read("run-1", "manifest.json") == b'{"ok":true}'
    assert list(tmp_path.rglob("*.tmp")) == []


@pytest.mark.asyncio
async def test_failed_replace_preserves_prior_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Overwriting before replacement would destroy the prior checkpoint."""
    store = FileSystemArtifactStore(tmp_path)
    await store.write_atomic("run-1", "manifest.json", b"old")

    def fail_replace(source: Path, target: Path) -> None:
        raise OSError(f"cannot replace {source.name} with {target.name}")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="cannot replace"):
        await store.write_atomic("run-1", "manifest.json", b"new")

    assert await store.read("run-1", "manifest.json") == b"old"
    assert list(tmp_path.rglob("*.tmp")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("run_id", "artifact"),
    [
        ("../other-run", "manifest.json"),
        ("run-1", "../secret"),
        ("run-1", "/tmp/secret"),
        ("run/child", "manifest.json"),
    ],
)
async def test_store_rejects_paths_outside_selected_root(
    tmp_path: Path, run_id: str, artifact: str
) -> None:
    """Removing path containment checks would permit output-directory escape."""
    store = FileSystemArtifactStore(tmp_path)
    with pytest.raises(UnsafeArtifactPathError):
        await store.write_atomic(run_id, artifact, b"unsafe")


@pytest.mark.asyncio
async def test_list_returns_relative_artifacts_in_sorted_order(tmp_path: Path) -> None:
    """Returning filesystem iteration order would make manifests nondeterministic."""
    store = FileSystemArtifactStore(tmp_path)
    await store.write_atomic("run-1", "sources/z.txt", b"z")
    await store.write_atomic("run-1", "manifest.json", b"m")
    await store.write_atomic("run-1", "sources/a.txt", b"a")

    assert await store.list("run-1") == [
        "manifest.json",
        "sources/a.txt",
        "sources/z.txt",
    ]


@pytest.mark.asyncio
async def test_read_missing_artifact_returns_none(tmp_path: Path) -> None:
    """Treating a missing checkpoint as an I/O crash would prevent first runs."""
    store = FileSystemArtifactStore(tmp_path)
    assert await store.read("run-1", "manifest.json") is None

