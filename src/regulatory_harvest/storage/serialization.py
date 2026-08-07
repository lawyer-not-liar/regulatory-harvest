"""Deterministic serialization and hashing helpers."""

import hashlib
import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


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
    """Hash a bundle's canonical JSON while excluding its self-hash field."""
    payload = bundle.model_dump(mode="json")
    payload.pop("bundle_hash", None)
    return sha256_digest(canonical_json_bytes(payload))
