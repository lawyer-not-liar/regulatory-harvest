"""Atomic filesystem artifact storage."""

import os
import uuid
from pathlib import Path, PurePosixPath


class UnsafeArtifactPathError(ValueError):
    """Raised when a run or artifact path could escape the selected root."""


class FileSystemArtifactStore:
    """Store run artifacts beneath a caller-selected directory."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve(strict=False)

    def _run_path(self, run_id: str) -> Path:
        if (
            not run_id
            or run_id in {".", ".."}
            or "/" in run_id
            or "\\" in run_id
            or Path(run_id).is_absolute()
        ):
            raise UnsafeArtifactPathError("run_id must be one safe path component")
        return self.root / run_id

    def _artifact_path(self, run_id: str, artifact: str) -> Path:
        if not artifact or "\\" in artifact:
            raise UnsafeArtifactPathError("artifact must use a safe relative POSIX path")
        relative = PurePosixPath(artifact)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise UnsafeArtifactPathError("artifact must use a safe relative POSIX path")

        candidate = self._run_path(run_id).joinpath(*relative.parts)
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(self.root):
            raise UnsafeArtifactPathError("artifact resolves outside the selected root")
        return candidate

    async def read(self, run_id: str, artifact: str) -> bytes | None:
        target = self._artifact_path(run_id, artifact)
        if not target.exists():
            return None
        if target.is_symlink() or not target.is_file():
            raise UnsafeArtifactPathError("artifact is not a regular file")
        return target.read_bytes()

    async def write_atomic(self, run_id: str, artifact: str, data: bytes) -> None:
        target = self._artifact_path(run_id, artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    async def list(self, run_id: str) -> list[str]:
        run_path = self._run_path(run_id)
        if not run_path.exists():
            return []
        if run_path.is_symlink() or not run_path.is_dir():
            raise UnsafeArtifactPathError("run path is not a regular directory")
        artifacts = [
            path.relative_to(run_path).as_posix()
            for path in run_path.rglob("*")
            if path.is_file() and not path.is_symlink() and not path.name.endswith(".tmp")
        ]
        return sorted(artifacts)

