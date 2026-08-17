"""Optional provider interfaces."""

from regulatory_harvest.analysis import AnalysisDraft

from .agent_draft import AgentDraftModelProvider
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
    "AgentDraftModelProvider",
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
