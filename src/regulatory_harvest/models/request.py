"""Research request models."""

import ipaddress
from datetime import date
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, field_validator

from .base import StrictModel
from .enums import SourceQuality, SourceRole


def _non_blank(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be blank")
    return stripped


def _optional_non_blank(value: str | None) -> str | None:
    if value is None:
        return None
    return _non_blank(value)


def _public_http_url(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = _non_blank(value)
    parsed = urlsplit(stripped)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("canonical_url must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("canonical_url must not contain credentials")
    if parsed.hostname is None:
        raise ValueError("canonical_url requires a hostname")
    hostname = parsed.hostname.rstrip(".").casefold()
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        if (
            "." not in hostname
            or hostname == "localhost"
            or hostname.endswith((".localhost", ".local", ".internal", ".home.arpa"))
        ):
            raise ValueError("canonical_url must identify a public authority") from None
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("canonical_url must identify a public authority")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class SourceInput(StrictModel):
    location: str
    canonical_url: str | None = None
    title: str | None = None
    publisher: str | None = None
    jurisdiction: str | None = None
    authority_type: str | None = None
    citation: str | None = None
    effective_date: str | None = None
    supersession: str | None = None
    language: str | None = None
    source_quality: SourceQuality = SourceQuality.UNKNOWN
    source_role: SourceRole | None = None
    license_assertion: str = "unknown"

    _validate_location = field_validator("location")(_non_blank)
    _validate_canonical_url = field_validator("canonical_url")(_public_http_url)
    _validate_language = field_validator("language")(_optional_non_blank)


class ResearchRequest(StrictModel):
    request_id: str
    question: str
    matter_title: str | None = None
    jurisdictions: list[str] = Field(min_length=1)
    as_of: date
    source_mode: Literal["provided-only", "web"] = "provided-only"
    source_inputs: list[SourceInput] = Field(min_length=1)
    context: str | None = None
    excluded_topics: list[str] = Field(default_factory=list)
    output_instructions: str | None = None

    _validate_required_text = field_validator("request_id", "question")(_non_blank)
    _validate_matter_title = field_validator("matter_title")(_optional_non_blank)

    @field_validator("jurisdictions")
    @classmethod
    def validate_jurisdictions(cls, values: list[str]) -> list[str]:
        normalized = [_non_blank(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("jurisdictions must be unique")
        return normalized
