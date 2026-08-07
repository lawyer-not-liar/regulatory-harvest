"""Transparent source-quality classification."""

from regulatory_harvest.models import SourceQuality


def classify_source_quality(declared: SourceQuality, normalized_text: str) -> SourceQuality:
    """Preserve caller declarations while marking empty sources unusable."""
    if not normalized_text.strip():
        return SourceQuality.UNUSABLE
    return declared

