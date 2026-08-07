"""Storage protocol for portable run artifacts."""

from typing import Protocol


class ArtifactStore(Protocol):
    async def read(self, run_id: str, artifact: str) -> bytes | None:
        """Return artifact bytes, or ``None`` when the artifact does not exist."""
        ...

    async def write_atomic(self, run_id: str, artifact: str, data: bytes) -> None:
        """Replace an artifact atomically."""
        ...

    async def list(self, run_id: str) -> list[str]:
        """List artifact paths relative to the selected run directory."""
        ...

