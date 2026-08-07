"""Stable fingerprints for stage inputs and provider configuration."""

from regulatory_harvest.models import StageName
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def stage_fingerprint(
    stage: StageName,
    upstream: bytes,
    *,
    implementation_version: str,
    configuration_fingerprint: str,
) -> str:
    """Fingerprint one stage without timestamps, credentials, or object identities."""
    return sha256_digest(
        canonical_json_bytes(
            {
                "configuration_fingerprint": configuration_fingerprint,
                "implementation_version": implementation_version,
                "stage": stage.value,
                "upstream_sha256": sha256_digest(upstream),
            }
        )
    )


def combined_configuration_fingerprint(values: dict[str, str]) -> str:
    """Hash caller-supplied safe adapter fingerprints."""
    return sha256_digest(canonical_json_bytes(values))
