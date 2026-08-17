"""Transparent source-quality classification."""

from urllib.parse import urlsplit

from regulatory_harvest.models import SourceQuality

_OFFICIAL_LEGAL_HOSTS = (
    "legislation.gov.uk",
    "eur-lex.europa.eu",
    "fedlex.admin.ch",
)
_PRIMARY_AUTHORITY_TERMS = (
    "act",
    "bill",
    "case",
    "code",
    "constitution",
    "decision",
    "directive",
    "guidance",
    "judgment",
    "law",
    "order",
    "ordinance",
    "regulation",
    "rule",
    "statute",
    "treaty",
)


def _official_legal_host(url: str | None) -> bool:
    if not url:
        return False
    hostname = urlsplit(url).hostname
    if hostname is None:
        return False
    normalized = hostname.rstrip(".").casefold()
    return any(
        normalized == host or normalized.endswith(f".{host}")
        for host in _OFFICIAL_LEGAL_HOSTS
    )


def _legal_instrument(authority_type: str | None) -> bool:
    if authority_type is None:
        return False
    words = authority_type.casefold().replace("-", " ").split()
    return any(term in words for term in _PRIMARY_AUTHORITY_TERMS)


def classify_source_quality(
    declared: SourceQuality,
    normalized_text: str,
    *,
    origin: str | None = None,
    canonical_url: str | None = None,
    authority_type: str | None = None,
) -> SourceQuality:
    """Preserve declarations and infer primary quality only from supported provenance."""
    if not normalized_text.strip():
        return SourceQuality.UNUSABLE
    if declared is not SourceQuality.UNKNOWN:
        return declared
    if _official_legal_host(canonical_url or origin) and _legal_instrument(authority_type):
        return SourceQuality.PRIMARY
    return declared
