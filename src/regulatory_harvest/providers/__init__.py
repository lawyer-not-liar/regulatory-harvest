"""Optional provider interfaces."""

from regulatory_harvest.analysis import AnalysisDraft

from .errors import ProviderError
from .protocols import (
    ModelProvider,
    ModelRequest,
    ModelResponse,
    SearchProvider,
    SearchQuery,
    SearchResult,
    SourceExcerpt,
    SourceFetcher,
)

__all__ = [
    "AnalysisDraft",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderError",
    "SearchProvider",
    "SearchQuery",
    "SearchResult",
    "SourceExcerpt",
    "SourceFetcher",
]
