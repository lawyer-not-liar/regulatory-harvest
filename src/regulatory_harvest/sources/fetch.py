"""Default local-file and supplied-URL source fetcher."""

import mimetypes
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from regulatory_harvest.models import (
    FetchStatus,
    SourceFailure,
    SourceInput,
    SourceQuality,
    SourceRecord,
)
from regulatory_harvest.storage import sha256_digest

from .normalize import NormalizationError, normalize_content
from .quality import classify_source_quality
from .security import UnsafeSourceError, validate_public_url


class SourceTooLargeError(ValueError):
    """Raised when source bytes exceed the configured limit."""


_LOCAL_MEDIA_TYPES = {
    ".htm": "text/html",
    ".html": "text/html",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
}


class DefaultSourceFetcher:
    """Fetch local files and explicit public HTTP(S) sources."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        base_dir: Path | None = None,
        max_bytes: int = 10 * 1024 * 1024,
        timeout_seconds: float = 20.0,
        max_redirects: int = 5,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._client = client
        self.base_dir = base_dir.resolve(strict=False) if base_dir is not None else None
        self.max_bytes = max_bytes
        self.timeout = httpx.Timeout(timeout_seconds)
        self.max_redirects = max_redirects

    async def fetch(self, source_input: SourceInput) -> SourceRecord:
        location = source_input.location
        parsed = urlsplit(location)
        try:
            if parsed.scheme in {"http", "https"}:
                data, media_type, final_origin = await self._fetch_url(location)
                display_name = source_input.title or parsed.hostname or location
            elif parsed.scheme:
                raise UnsafeSourceError("source location uses an unsupported URL scheme")
            else:
                data, media_type, final_origin = self._fetch_local(Path(location))
                display_name = source_input.title or Path(location).name

            normalized = normalize_content(data, media_type)
            if not normalized.text.strip():
                raise NormalizationError("source contained no extractable text")
            content_hash = sha256_digest(normalized.text.encode("utf-8"))
            source_id = self._source_id(final_origin, content_hash)
            return SourceRecord(
                source_id=source_id,
                origin=final_origin,
                display_name=display_name,
                retrieved_at=datetime.now(UTC),
                content_hash=content_hash,
                media_type=normalized.media_type,
                normalized_text=normalized.text,
                normalization_warnings=list(normalized.warnings),
                canonical_url=source_input.canonical_url,
                title=source_input.title,
                publisher=source_input.publisher,
                jurisdiction=source_input.jurisdiction,
                authority_type=source_input.authority_type,
                citation=source_input.citation,
                effective_date=source_input.effective_date,
                supersession=source_input.supersession,
                language=source_input.language,
                license_assertion=source_input.license_assertion,
                source_quality=classify_source_quality(
                    source_input.source_quality,
                    normalized.text,
                    origin=final_origin,
                    canonical_url=source_input.canonical_url,
                    authority_type=source_input.authority_type,
                ),
                source_role=source_input.source_role,
            )
        except Exception as error:
            return self._failed_record(source_input, error)

    def _fetch_local(self, path: Path) -> tuple[bytes, str, str]:
        media_type = _LOCAL_MEDIA_TYPES.get(path.suffix.lower())
        if media_type is None:
            guessed, _ = mimetypes.guess_type(path.name)
            media_type = guessed or "application/octet-stream"
        read_path = path
        if not path.is_absolute() and self.base_dir is not None:
            read_path = self.base_dir / path
        data = read_path.read_bytes()
        if len(data) > self.max_bytes:
            raise SourceTooLargeError("source exceeded the configured byte limit")
        return data, media_type, str(path)

    async def _fetch_url(self, url: str) -> tuple[bytes, str, str]:
        if self._client is not None:
            return await self._download(self._client, url)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout,
            headers={"User-Agent": "regulatory-harvest/0.1"},
        ) as client:
            return await self._download(client, url)

    async def _download(
        self, client: httpx.AsyncClient, initial_url: str
    ) -> tuple[bytes, str, str]:
        current_url = initial_url
        for redirect_count in range(self.max_redirects + 1):
            validate_public_url(current_url)
            async with client.stream("GET", current_url, follow_redirects=False) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if location is None:
                        raise httpx.HTTPStatusError(
                            "redirect response omitted Location",
                            request=response.request,
                            response=response,
                        )
                    if redirect_count >= self.max_redirects:
                        raise httpx.TooManyRedirects(
                            "source exceeded redirect limit", request=response.request
                        )
                    current_url = urljoin(current_url, location)
                    continue

                response.raise_for_status()
                declared_length = response.headers.get("content-length")
                if declared_length is not None and int(declared_length) > self.max_bytes:
                    raise SourceTooLargeError("source exceeded the configured byte limit")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        raise SourceTooLargeError("source exceeded the configured byte limit")
                media_type = response.headers.get("content-type", "application/octet-stream")
                return bytes(body), media_type, str(response.url)
        raise httpx.TooManyRedirects("source exceeded redirect limit")

    @staticmethod
    def _source_id(origin: str, content_hash: str) -> str:
        identity = sha256_digest(f"{origin}\0{content_hash}".encode())
        return f"src_{identity[:24]}"

    def _failed_record(self, source_input: SourceInput, error: Exception) -> SourceRecord:
        origin = source_input.location
        if isinstance(error, UnsafeSourceError):
            category = "unsafe_source"
            retryable = False
        elif isinstance(error, SourceTooLargeError):
            category = "source_too_large"
            retryable = False
        elif isinstance(error, NormalizationError):
            category = "normalization_error"
            retryable = False
        elif isinstance(error, httpx.HTTPStatusError):
            category = "http_error"
            retryable = error.response.status_code == 429 or error.response.status_code >= 500
        elif isinstance(error, (httpx.TimeoutException, httpx.NetworkError)):
            category = "network_error"
            retryable = True
        elif isinstance(error, OSError):
            category = "file_error"
            retryable = False
        else:
            category = "source_error"
            retryable = False

        status_code = (
            error.response.status_code if isinstance(error, httpx.HTTPStatusError) else None
        )
        return SourceRecord(
            source_id=f"src_{sha256_digest(origin.encode())[:24]}",
            origin=origin,
            display_name=source_input.title or Path(urlsplit(origin).path).name or origin,
            retrieved_at=datetime.now(UTC),
            content_hash=None,
            media_type="application/octet-stream",
            normalized_text="",
            canonical_url=source_input.canonical_url,
            title=source_input.title,
            publisher=source_input.publisher,
            jurisdiction=source_input.jurisdiction,
            authority_type=source_input.authority_type,
            citation=source_input.citation,
            effective_date=source_input.effective_date,
            supersession=source_input.supersession,
            language=source_input.language,
            license_assertion=source_input.license_assertion,
            source_quality=SourceQuality.UNUSABLE,
            source_role=source_input.source_role,
            fetch_status=FetchStatus.FAILED,
            error=SourceFailure(
                category=category,
                retryable=retryable,
                message=str(error) or type(error).__name__,
                provider_status_code=status_code,
            ),
        )
