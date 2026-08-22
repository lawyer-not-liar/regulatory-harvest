"""Fail-closed evaluator protocol detection over the sealed run manifest."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import cast

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_artifacts import EvaluationIntegrityError, read_evaluation_artifact
from .attorney_v22_requests import COMPILER_CONTRACT_FINGERPRINT_V22

_MANIFEST_PATH = "run-manifest.json"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_SUPPORTED_PROTOCOLS = frozenset({"1.3", "2.0", "2.1", "2.2"})


def _unsupported() -> EvaluationIntegrityError:
    return EvaluationIntegrityError("EVALUATION_PROTOCOL_UNSUPPORTED")


def _ordinary_json(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise _unsupported()
        if current is None or type(current) in {str, bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise _unsupported()
            continue
        if type(current) is dict:
            mapping = cast(dict[object, object], current)
            if any(type(key) is not str for key in mapping):
                raise _unsupported()
            pending.extend((item, depth + 1) for item in mapping.values())
            continue
        if type(current) is list:
            pending.extend((item, depth + 1) for item in cast(list[object], current))
            continue
        raise _unsupported()


def _bounded_manifest_version(run_dir: Path) -> str:
    try:
        data = read_evaluation_artifact(run_dir, _MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES)
    except (EvaluationIntegrityError, OSError, TypeError, ValueError) as error:
        raise _unsupported() from error
    if type(data) is not bytes or len(data) > _MAX_JSON_BYTES:
        raise _unsupported()
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise _unsupported() from error
    _ordinary_json(payload)
    try:
        if canonical_json_bytes(payload) != data:
            raise _unsupported()
    except (TypeError, ValueError, RecursionError) as error:
        raise _unsupported() from error
    if type(payload) is not dict:
        raise _unsupported()
    manifest = cast(dict[str, object], payload)
    protocol_version = manifest.get("protocol_version")
    schema_version = manifest.get("schema_version")
    compiler_contract = manifest.get("compiler_contract_fingerprint")
    if protocol_version in {"2.0", "2.1"} and schema_version is None and compiler_contract is None:
        return protocol_version
    if (
        protocol_version == "2.2"
        and schema_version is None
        and compiler_contract == COMPILER_CONTRACT_FINGERPRINT_V22
    ):
        return "2.2"
    if schema_version == "1.3" and protocol_version is None:
        return "1.3"
    raise _unsupported()


def detect_evaluation_protocol(run_dir: Path) -> str:
    """Return the exact supported manifest generation without replaying it."""
    manifest = _bounded_manifest_version(run_dir)
    if manifest not in _SUPPORTED_PROTOCOLS:
        raise _unsupported()
    return manifest
