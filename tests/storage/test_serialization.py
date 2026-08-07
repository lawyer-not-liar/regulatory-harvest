from datetime import date

from regulatory_harvest.models import ResearchRequest, SourceInput
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def test_canonical_json_sorts_mapping_keys_without_extra_whitespace() -> None:
    """Changing serializer ordering or separators would destabilize fingerprints."""
    assert canonical_json_bytes({"z": 1, "a": 2}) == b'{"a":2,"z":1}'


def test_canonical_json_serializes_pydantic_dates_and_enums() -> None:
    """Using the default JSON encoder would fail on typed request values."""
    request = ResearchRequest(
        request_id="demo",
        question="What applies?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="rule.txt")],
    )

    data = canonical_json_bytes(request)

    assert b'"as_of":"2026-08-05"' in data
    assert b'"source_quality":"unknown"' in data


def test_sha256_digest_matches_hand_checked_value() -> None:
    """Changing the digest algorithm would break portable content identities."""
    assert sha256_digest(b"harvest") == (
        "d087ee8196afa2ff461aed248e9b90d5cca64e9fa0dfdbec351849610ae12c47"
    )
