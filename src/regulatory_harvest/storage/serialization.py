"""Deterministic serialization and hashing helpers."""

import hashlib
import json
from copy import deepcopy
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar, cast

from pydantic import BaseModel

_BundleModel = TypeVar("_BundleModel", bound=BaseModel)
_EXPANDED_SCHEMA_10_SOURCE_INPUT_FIELDS = frozenset(
    {"publisher", "effective_date", "supersession"}
)


def _legacy_schema_10_shape(bundle: BaseModel) -> str:
    """Identify either exact schema-1.0 shape from preserved input-field presence."""
    request = getattr(bundle, "request", None)
    source_inputs = getattr(request, "source_inputs", None)
    if not isinstance(request, BaseModel) or not isinstance(source_inputs, list):
        raise ValueError("schema 1.0 bundle has no inspectable request shape")
    if not source_inputs or any(not isinstance(item, BaseModel) for item in source_inputs):
        raise ValueError("schema 1.0 bundle has no inspectable source-input shape")

    source_mode_present = "source_mode" in request.model_fields_set
    initial_source_inputs = all(
        _EXPANDED_SCHEMA_10_SOURCE_INPUT_FIELDS.isdisjoint(item.model_fields_set)
        for item in source_inputs
    )
    expanded_source_inputs = all(
        item.model_fields_set >= _EXPANDED_SCHEMA_10_SOURCE_INPUT_FIELDS
        for item in source_inputs
    )
    if not source_mode_present and initial_source_inputs:
        return "initial"
    if source_mode_present and expanded_source_inputs:
        return "expanded"
    raise ValueError("schema 1.0 bundle mixes incompatible historical field shapes")


def _require_legacy_defaults(payload: dict[str, Any]) -> None:
    request = cast(dict[str, Any], payload["request"])
    checks: list[tuple[bool, str]] = [
        (payload.get("brief") is None, "brief"),
        (request.get("matter_title") is None, "request.matter_title"),
    ]
    for index, source_input in enumerate(cast(list[dict[str, Any]], request["source_inputs"])):
        for field in (
            "canonical_url",
            "language",
            "source_role",
        ):
            checks.append(
                (
                    source_input.get(field) is None,
                    f"request.source_inputs[{index}].{field}",
                )
            )
    for index, source in enumerate(cast(list[dict[str, Any]], payload["sources"])):
        for field in ("canonical_url", "language", "source_role"):
            checks.append((source.get(field) is None, f"sources[{index}].{field}"))
    for index, issue in enumerate(cast(list[dict[str, Any]], payload["issues"])):
        checks.extend(
            (
                (issue.get("category") == "other", f"issues[{index}].category"),
                (
                    issue.get("presentation_role") is None,
                    f"issues[{index}].presentation_role",
                ),
            )
        )
    for finding_index, finding in enumerate(
        cast(list[dict[str, Any]], payload["findings"])
    ):
        for claim_index, claim in enumerate(cast(list[dict[str, Any]], finding["claims"])):
            checks.append(
                (
                    claim.get("enforcement_roles") == [],
                    f"findings[{finding_index}].claims[{claim_index}].enforcement_roles",
                )
            )
    for index, gap in enumerate(cast(list[dict[str, Any]], payload["gaps"])):
        checks.extend(
            (
                (gap.get("category") == "other", f"gaps[{index}].category"),
                (
                    gap.get("presentation_role") is None,
                    f"gaps[{index}].presentation_role",
                ),
            )
        )
    invalid = [location for valid, location in checks if not valid]
    if invalid:
        raise ValueError(
            "schema 1.0 bundle contains post-1.0 content at " + ", ".join(invalid)
        )


def _legacy_schema_10_projection(
    bundle: BaseModel,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return the exact field shape used by the original schema-1.0 model."""
    historical_shape = _legacy_schema_10_shape(bundle)
    _require_legacy_defaults(payload)
    projected = deepcopy(payload)
    projected.pop("brief", None)
    request = cast(dict[str, Any], projected["request"])
    request.pop("matter_title", None)
    if historical_shape == "initial":
        request.pop("source_mode", None)
    for source_input in cast(list[dict[str, Any]], request["source_inputs"]):
        fields = ["canonical_url", "language", "source_role"]
        if historical_shape == "initial":
            fields.extend(_EXPANDED_SCHEMA_10_SOURCE_INPUT_FIELDS)
        for field in fields:
            source_input.pop(field, None)
    for source in cast(list[dict[str, Any]], projected["sources"]):
        for field in ("canonical_url", "language", "source_role"):
            source.pop(field, None)
    for issue in cast(list[dict[str, Any]], projected["issues"]):
        issue.pop("category", None)
        issue.pop("presentation_role", None)
    for finding in cast(list[dict[str, Any]], projected["findings"]):
        for claim in cast(list[dict[str, Any]], finding["claims"]):
            claim.pop("enforcement_roles", None)
    for gap in cast(list[dict[str, Any]], projected["gaps"]):
        gap.pop("category", None)
        gap.pop("presentation_role", None)
    return projected


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a value to stable UTF-8 JSON without presentation whitespace."""
    serializable = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        serializable,
        default=_json_default,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return a lowercase SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def calculate_bundle_hash(bundle: BaseModel) -> str:
    """Hash a bundle under its declared current or exact historical contract."""
    payload = bundle.model_dump(mode="json")
    payload.pop("bundle_hash", None)
    schema_version = payload.get("schema_version")
    if schema_version == "1.0":
        payload = _legacy_schema_10_projection(bundle, payload)
    elif schema_version != "1.1":
        raise ValueError("unsupported bundle schema version")
    return sha256_digest(canonical_json_bytes(payload))


def migrate_bundle_hash_contract(bundle: _BundleModel) -> _BundleModel:
    """Verify a bundle, then copy it into the current schema/hash contract."""
    stored_hash = getattr(bundle, "bundle_hash", None)
    if stored_hash is None or stored_hash != calculate_bundle_hash(bundle):
        raise ValueError("bundle must have a valid source-schema hash before migration")
    migrated = bundle.model_copy(
        deep=True,
        update={"schema_version": "1.1", "bundle_hash": None},
    )
    return migrated.model_copy(
        update={"bundle_hash": calculate_bundle_hash(migrated)}
    )
