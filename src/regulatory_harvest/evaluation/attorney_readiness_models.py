"""Strict persisted contracts for the delivery-readiness-v1 companion protocol.

This module contains value contracts and the canonical policy loader only.
Input admission, request construction, draft compilation, readiness derivation,
storage, replay, and workflow transitions belong to later dedicated modules.
"""

from __future__ import annotations

import json
import math
import re
import warnings
from collections.abc import Iterable, Mapping
from datetime import date, datetime, time
from enum import Enum, StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self, TypeVar, cast, get_origin

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_baseline_models import (
    BaselineImportanceV1,
    GradeableBaselineProjectionV1,
    ImportanceBasisV1,
    validate_importance_rationale_v1,
)
from .attorney_models import ArtifactRecord
from .attorney_v2_models import AbsoluteDispositionV2, RequirementGradeV2

READINESS_PROTOCOL_V1: Literal["delivery-readiness-v1"] = "delivery-readiness-v1"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_REQUIREMENT_REF_PATTERN = r"^REQ-[0-9]{4}$"
_BATCH_REF_PATTERN = r"^GB-[12]-[0-9]{4}$"
_CONTESTED_REF_PATTERN = r"^CONT-[0-9]{4}$"
_GAP_CANDIDATE_PATTERN = r"^GC-[0-9]{4}$"
_SAFETY_DISPUTE_PATTERN = r"^SD-[0-9]{4}$"
_GAP_REF_PATTERN = r"^GAP-[0-9]{4}$"
_SOURCE_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]*"
_EVIDENCE_REF_PATTERN = (
    r"^(?:SOURCE-[0-9]{6}|BASELINE-REQ-[0-9]{4}|BASELINE-CONT-[0-9]{4}|"
    r"PREREQUISITE-(?:CURRENTNESS|COMPLETENESS|LANGUAGE)-"
    + _SOURCE_ID_PATTERN
    + r"|PREREQUISITE-CLIENT-FACTS)$"
)
_MAX_FRAGMENT_ITEMS = 5
_MAX_COMPILED_ITEMS = 640
_MAX_FINDINGS = 640
_MAX_EVIDENCE_REF_LENGTH = 256
_MAX_WIRE_BYTES = 16 * 1024 * 1024
_MAX_WIRE_DEPTH = 64
_MAX_WIRE_NODES = 100_000
_READINESS_PROJECTION_ATTESTATION = object()

Hash = Annotated[str, Field(pattern=_HASH_PATTERN, strict=True)]
RequirementRef = Annotated[str, Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)]
BatchRef = Annotated[str, Field(pattern=_BATCH_REF_PATTERN, strict=True)]
ContestedRef = Annotated[str, Field(pattern=_CONTESTED_REF_PATTERN, strict=True)]
GapCandidateRef = Annotated[str, Field(pattern=_GAP_CANDIDATE_PATTERN, strict=True)]
SafetyDisputeRef = Annotated[str, Field(pattern=_SAFETY_DISPUTE_PATTERN, strict=True)]
GapRef = Annotated[str, Field(pattern=_GAP_REF_PATTERN, strict=True)]
EvidenceRefV1 = Annotated[
    str,
    Field(
        max_length=_MAX_EVIDENCE_REF_LENGTH,
        pattern=_EVIDENCE_REF_PATTERN,
        strict=True,
    ),
]

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _nonblank(value: str) -> str:
    checked = value.strip()
    if not checked:
        raise ValueError("value must not be blank")
    return checked


def _preserve_nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("value must not be blank")
    return value


def _optional_nonblank(value: str | None) -> str | None:
    return None if value is None else _nonblank(value)


def _unique_nonblank(values: tuple[str, ...], *, location: str) -> tuple[str, ...]:
    checked = tuple(_nonblank(value) for value in values)
    if len(checked) != len(set(checked)):
        raise ValueError(f"{location} must be unique")
    return checked


def _unique_evidence_refs(
    values: object,
    *,
    location: str,
) -> object:
    if type(values) not in {list, tuple} and type(values) is not _FrozenWireTuple:
        raise ValueError(f"{location} must use a built-in list or tuple")
    checked_values = cast(list[object] | tuple[object, ...], values)
    if len(checked_values) > _MAX_FINDINGS:
        raise ValueError(f"{location} exceeds the bounded inventory count")
    if any(
        type(value) is not str
        or len(value) > _MAX_EVIDENCE_REF_LENGTH
        or re.fullmatch(_EVIDENCE_REF_PATTERN, value) is None
        for value in checked_values
    ):
        raise ValueError(f"{location} contains an invalid controller evidence handle")
    checked_refs = cast(list[str] | tuple[str, ...], checked_values)
    if len(checked_refs) != len(set(checked_refs)):
        raise ValueError(f"{location} must be unique")
    return values


def _unique_exact_passages(values: object, *, location: str) -> object:
    if type(values) not in {list, tuple} and type(values) is not _FrozenWireTuple:
        raise ValueError(f"{location} must use a built-in list or tuple")
    checked_values = cast(list[object] | tuple[object, ...], values)
    exact_values: tuple[object, ...] = tuple(checked_values)
    if any(type(value) is not str for value in exact_values):
        raise ValueError(f"{location} must contain native strings")
    exact_strings = cast(tuple[str, ...], exact_values)
    if any(not value.strip() for value in exact_strings):
        raise ValueError(f"{location} must not contain blank values")
    if len(exact_strings) != len(set(exact_strings)):
        raise ValueError(f"{location} must be unique by exact bytes")
    return values


def _validate_requirement_grade_passages(values: object) -> object:
    if type(values) not in {list, tuple} and type(values) is not _FrozenWireTuple:
        raise ValueError("requirement grades must use a built-in list or tuple")
    checked_values = cast(list[object] | tuple[object, ...], values)
    for grade in checked_values:
        if type(grade) is dict and "report_passages" in grade:
            _unique_exact_passages(
                grade["report_passages"],
                location="requirement grade report passages",
            )
    return values


def _strict_lane(value: object) -> object:
    if type(value) is not int or value not in {1, 2}:
        raise ValueError("lane must be the native integer 1 or 2")
    return value


def _strict_attempt(value: object) -> object:
    if type(value) is not int or value not in {1, 2}:
        raise ValueError("attempt must be the native integer 1 or 2")
    return value


def _safe_call_id(value: str | None) -> str | None:
    if value is None:
        return None
    patterns = (
        r"grade-lane-([12])-GB-\1-[0-9]{4}",
        r"contested-grade-lane-[12]-CONT-[0-9]{4}",
        r"safety-lane-[12]",
        r"safety-referee-SD-[0-9]{4}",
    )
    if not any(re.fullmatch(pattern, value) is not None for pattern in patterns):
        raise ValueError("current call ID must use the closed readiness identifier grammar")
    return value


def _add_projection_wire_cost(budget: list[int], amount: int) -> None:
    budget[1] += amount
    if budget[1] > _MAX_WIRE_BYTES:
        raise ValueError("gradeable projection exceeds readiness wire limits")


def _add_projection_text_cost(value: str, budget: list[int]) -> None:
    _add_projection_wire_cost(budget, len(value) + 2)
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\"}:
            extra = 1
        elif codepoint < 0x20:
            extra = 5
        elif codepoint < 0x80:
            extra = 0
        elif codepoint < 0x800:
            extra = 1
        elif codepoint < 0x10000:
            extra = 2
        else:
            extra = 3
        if extra:
            _add_projection_wire_cost(budget, extra)


def _preflight_projection_native_state(
    value: object,
    active: set[int],
    *,
    budget: list[int],
    depth: int,
) -> None:
    """Bound exact projection native state without serializing or hashing it."""
    budget[0] += 1
    if budget[0] > _MAX_WIRE_NODES or depth > _MAX_WIRE_DEPTH:
        raise ValueError("gradeable projection exceeds readiness wire limits")
    if type(value) is str:
        _add_projection_text_cost(value, budget)
        return
    if type(value) is bytes:
        _add_projection_wire_cost(budget, len(value) + 2)
        for item in value:
            extra = 5 if item < 0x20 else 1 if item in {0x22, 0x5C} else 0
            if extra:
                _add_projection_wire_cost(budget, extra)
        return
    if value is None or type(value) is bool:
        _add_projection_wire_cost(budget, 5)
        return
    if type(value) is int:
        _add_projection_wire_cost(budget, max(1, value.bit_length() + 1))
        return
    if type(value) is float:
        _add_projection_wire_cost(budget, 32)
        return
    if isinstance(value, Enum):
        _preflight_projection_native_state(
            value.value,
            active,
            budget=budget,
            depth=depth + 1,
        )
        return
    if isinstance(value, (datetime, date, time)):
        _add_projection_text_cost(value.isoformat(), budget)
        return
    if isinstance(value, Mapping) and not isinstance(value, dict):
        raise ValueError("gradeable projection requires built-in mappings")
    if isinstance(value, BaseModel):
        children: object = dict(object.__getattribute__(value, "__dict__"))
    else:
        children = value
    if isinstance(children, dict):
        identity = id(value)
        if identity in active:
            raise ValueError("gradeable projection contains a cycle")
        active.add(identity)
        try:
            _add_projection_wire_cost(budget, 2)
            for key, item in dict.items(children):
                if type(key) is not str:
                    raise ValueError("gradeable projection keys must be strings")
                _add_projection_text_cost(key, budget)
                _add_projection_wire_cost(budget, 2)
                _preflight_projection_native_state(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
            return
        finally:
            active.remove(identity)
    if isinstance(children, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise ValueError("gradeable projection contains a cycle")
        active.add(identity)
        try:
            _add_projection_wire_cost(budget, len(children) + 2)
            for item in children:
                _preflight_projection_native_state(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
            return
        finally:
            active.remove(identity)
    raise ValueError("gradeable projection contains unsupported native state")


def _exact_gradeable_projection_wire(
    value: object,
    *,
    prior_budget: list[int],
    depth: int,
) -> dict[str, object]:
    """Reconstruct the exact stable projection through its prerequisite proof model."""
    if type(value) is not GradeableBaselineProjectionV1:
        raise ValueError("gradeable projection handoff must use the exact stable class")
    projection = value
    preflight_budget = list(prior_budget)
    _preflight_projection_native_state(
        projection,
        set(),
        budget=preflight_budget,
        depth=depth,
    )
    if _contains_readiness_wire_marker(projection) and not _projection_is_attested(projection):
        raise ValueError("gradeable projection handoff has transplanted readiness state")
    serialized = projection.model_dump(mode="json", warnings="error")
    raw = dict(cast(dict[str, object], serialized))
    baseline_value = raw.get("baseline_input")
    if type(baseline_value) is not dict:
        raise ValueError("gradeable projection handoff has invalid baseline input")
    baseline_raw = dict(cast(dict[str, object], baseline_value))
    compiler_contract = baseline_raw.get("compiler_contract")
    baseline_raw["compiler_contract"] = json.loads(canonical_json_bytes(compiler_contract))
    for field_name in ("evaluation_rubric_bytes", "importance_policy_bytes"):
        field_value = baseline_raw.get(field_name)
        if type(field_value) is not str:
            raise ValueError("gradeable projection handoff has invalid policy bytes")
        baseline_raw[field_name] = field_value.encode("utf-8")
    raw["baseline_input"] = baseline_raw
    checked = GradeableBaselineProjectionV1.model_validate(raw)
    if canonical_json_bytes(checked.model_dump(mode="json", warnings="error")) != (
        canonical_json_bytes(serialized)
    ):
        raise ValueError("gradeable projection handoff failed exact reconstruction")
    return raw


def _is_trusted_serialization_exclusion(value: BaseModel, field_name: str) -> bool:
    """Recognize the one exact readiness-owned field omitted from canonical wire."""
    return (
        type(value) is ReadinessCallRecordV1
        and field_name == "context_token_fingerprint"
        and value.context_token_fingerprint is None
    )


def _wire_snapshot_inner(
    value: object,
    active: set[int],
    *,
    budget: list[int],
    depth: int,
) -> object:
    """Return one bounded raw view without normalizing scalar provenance."""
    budget[0] += 1
    if budget[0] > _MAX_WIRE_NODES or depth > _MAX_WIRE_DEPTH:
        raise ValueError("readiness model wire snapshot exceeds resource limits")
    if type(value) is str:
        budget[1] += len(value.encode("utf-8"))
    elif type(value) is bytes:
        budget[1] += len(value)
    else:
        budget[1] += 1
    if budget[1] > _MAX_WIRE_BYTES:
        raise ValueError("readiness model wire snapshot exceeds resource limits")
    if isinstance(value, Mapping) and not isinstance(value, dict):
        raise ValueError("readiness model wire snapshot requires a built-in mapping")
    if isinstance(value, dict) and type(value) not in {dict, _FrozenDict}:
        raise ValueError("readiness model wire snapshot requires built-in dictionaries")
    if isinstance(value, tuple) and type(value) not in {tuple, _FrozenWireTuple}:
        raise ValueError("readiness model wire snapshot requires built-in tuples")
    if isinstance(value, list) and type(value) not in {list, _FrozenJsonList}:
        raise ValueError("readiness model wire snapshot requires built-in lists")
    if type(value) is GradeableBaselineProjectionV1:
        return _wire_snapshot_inner(
            _exact_gradeable_projection_wire(
                value,
                prior_budget=budget,
                depth=depth,
            ),
            active,
            budget=budget,
            depth=depth + 1,
        )
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in active:
            raise ValueError("readiness model wire snapshot contains a cycle")
        active.add(identity)
        try:
            state = dict(object.__getattribute__(value, "__dict__"))
            extra = object.__getattribute__(value, "__pydantic_extra__")
            if extra:
                state.update(extra)
            serialized = value.model_dump(mode="json", warnings="error")
            for field_name in type(value).model_fields:
                if field_name in state and _is_trusted_serialization_exclusion(
                    value,
                    field_name,
                ):
                    state.pop(field_name)
            if _has_unmarked_json_array(state, serialized):
                raise ValueError("model state contains an unmarked JSON array tuple")
            return {
                key: _wire_snapshot_inner(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
                for key, item in dict.items(state)
            }
        finally:
            active.remove(identity)
    if isinstance(value, tuple):
        identity = id(value)
        if identity in active:
            raise ValueError("readiness model wire snapshot contains a cycle")
        active.add(identity)
        try:
            values = tuple(
                _wire_snapshot_inner(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
                for item in tuple.__iter__(cast(tuple[object, ...], value))
            )
            return values
        finally:
            active.remove(identity)
    if isinstance(value, list):
        identity = id(value)
        if identity in active:
            raise ValueError("readiness model wire snapshot contains a cycle")
        active.add(identity)
        try:
            return [
                _wire_snapshot_inner(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
                for item in list.__iter__(cast(list[object], value))
            ]
        finally:
            active.remove(identity)
    if isinstance(value, dict):
        identity = id(value)
        if identity in active:
            raise ValueError("readiness model wire snapshot contains a cycle")
        active.add(identity)
        try:
            result: dict[object, object] = {}
            for key, item in dict.items(value):
                wire_key = _wire_snapshot_inner(
                    key,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
                if wire_key in result:
                    raise ValueError("readiness model wire snapshot contains duplicate keys")
                result[wire_key] = _wire_snapshot_inner(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
            return result
        finally:
            active.remove(identity)
    return value


def _wire_snapshot(value: object) -> object:
    """Contain ordinary failures from traversal of one untrusted raw value."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return _wire_snapshot_inner(
                value,
                set(),
                budget=[0, 0],
                depth=1,
            )
    except Exception:
        raise ValueError("readiness model wire snapshot is invalid") from None


class _FrozenDict(dict[str, object]):
    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("delivery-readiness-v1 values are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable  # type: ignore[assignment]
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable


class _FrozenWireTuple(tuple[object, ...]):
    """Marker for a validated tuple field that serializes as a JSON array."""


class _FrozenJsonList(list[object]):
    """Immutable marker for a validated JSON list."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("delivery-readiness-v1 values are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable  # type: ignore[assignment]
    __imul__ = _immutable  # type: ignore[assignment]
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable


def _contains_readiness_wire_marker(
    value: object,
    active: set[int] | None = None,
    *,
    budget: list[int] | None = None,
    depth: int = 1,
) -> bool:
    checked_active = set() if active is None else active
    checked_budget = [0] if budget is None else budget
    checked_budget[0] += 1
    if checked_budget[0] > _MAX_WIRE_NODES or depth > _MAX_WIRE_DEPTH:
        raise ValueError("gradeable projection marker scan exceeds resource limits")
    if isinstance(value, (_FrozenDict, _FrozenWireTuple, _FrozenJsonList)):
        return True
    children: Iterable[object]
    if isinstance(value, BaseModel):
        children = dict(object.__getattribute__(value, "__dict__")).values()
    elif isinstance(value, dict):
        children = dict.values(value)
    elif isinstance(value, (list, tuple)):
        children = value
    else:
        return False
    identity = id(value)
    if identity in checked_active:
        raise ValueError("gradeable projection marker scan contains a cycle")
    checked_active.add(identity)
    try:
        return any(
            _contains_readiness_wire_marker(
                item,
                checked_active,
                budget=checked_budget,
                depth=depth + 1,
            )
            for item in children
        )
    finally:
        checked_active.remove(identity)


def _projection_is_attested(value: GradeableBaselineProjectionV1) -> bool:
    private = object.__getattribute__(value, "__pydantic_private__")
    return isinstance(private, dict) and (
        private.get("_readiness_projection_attestation") is _READINESS_PROJECTION_ATTESTATION
    )


def _attest_projection(value: GradeableBaselineProjectionV1) -> None:
    private = object.__getattribute__(value, "__pydantic_private__")
    checked = {} if private is None else dict(private)
    checked["_readiness_projection_attestation"] = _READINESS_PROJECTION_ATTESTATION
    object.__setattr__(value, "__pydantic_private__", checked)


def _json_key(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return value


def _has_unmarked_json_array(value: object, serialized: object) -> bool:
    """Detect tuples whose JSON-list provenance was not established by validation."""
    if isinstance(value, BaseModel):
        state = dict(object.__getattribute__(value, "__dict__"))
        for field_name in type(value).model_fields:
            if field_name in state and _is_trusted_serialization_exclusion(
                value,
                field_name,
            ):
                state.pop(field_name)
        return _has_unmarked_json_array(
            state,
            value.model_dump(mode="json", warnings="error"),
        )
    if isinstance(value, dict) and isinstance(serialized, dict):
        return any(
            _json_key(key) not in serialized
            or _has_unmarked_json_array(item, serialized[_json_key(key)])
            for key, item in dict.items(value)
        )
    if isinstance(value, tuple) and isinstance(serialized, list):
        if not isinstance(value, _FrozenWireTuple):
            return True
        return len(value) != len(serialized) or any(
            _has_unmarked_json_array(item, wire_item)
            for item, wire_item in zip(value, serialized, strict=True)
        )
    if isinstance(value, list) and isinstance(serialized, list):
        return len(value) != len(serialized) or any(
            _has_unmarked_json_array(item, wire_item)
            for item, wire_item in zip(value, serialized, strict=True)
        )
    return False


def _freeze_validated_wire(
    value: object,
    serialized: object,
    *,
    annotation: object | None = None,
) -> object:
    """Freeze one validated value while marking its exact JSON-array representation."""
    if isinstance(value, BaseModel):
        if not isinstance(serialized, dict):
            raise ValueError("validated readiness model has invalid serialized state")
        for field_name, field_info in type(value).model_fields.items():
            if field_name not in serialized:
                if _is_trusted_serialization_exclusion(value, field_name):
                    continue
                raise ValueError("validated readiness model is missing serialized state")
            item = getattr(value, field_name)
            frozen = _freeze_validated_wire(
                item,
                serialized[field_name],
                annotation=field_info.annotation,
            )
            if frozen is not item:
                object.__setattr__(value, field_name, frozen)
        return value
    if isinstance(value, dict):
        if not isinstance(serialized, dict):
            raise ValueError("validated readiness mapping has invalid serialized state")
        frozen_items: dict[object, object] = {}
        for key, item in dict.items(value):
            wire_key = _json_key(key)
            if wire_key not in serialized:
                raise ValueError("validated readiness mapping is missing serialized state")
            frozen_items[key] = _freeze_validated_wire(item, serialized[wire_key])
        return _FrozenDict(cast(dict[str, object], frozen_items))
    if isinstance(value, (list, tuple)):
        if not isinstance(serialized, list) or len(value) != len(serialized):
            raise ValueError("validated readiness sequence has invalid serialized state")
        frozen_sequence = (
            _freeze_validated_wire(item, wire_item)
            for item, wire_item in zip(value, serialized, strict=True)
        )
        if get_origin(annotation) is tuple:
            return _FrozenWireTuple(frozen_sequence)
        return _FrozenJsonList(frozen_sequence)
    return value


def _same_wire_value(raw: object, checked: object, serialized: object) -> bool:
    """Require exact supplied scalar provenance against one strict result."""
    if isinstance(raw, dict) and isinstance(checked, dict) and isinstance(serialized, dict):
        for raw_key, raw_value in dict.items(raw):
            if type(raw_key) is str:
                if raw_key not in serialized:
                    return False
                matching = [key for key in checked if _json_key(key) == raw_key]
            else:
                matching = [key for key in checked if type(key) is type(raw_key) and key == raw_key]
            if len(matching) != 1:
                return False
            checked_key = matching[0]
            json_key = _json_key(checked_key)
            if json_key not in serialized or not _same_wire_value(
                raw_value,
                checked[checked_key],
                serialized[json_key],
            ):
                return False
        return True
    if (
        isinstance(raw, list)
        and isinstance(checked, (list, tuple))
        and isinstance(serialized, list)
    ):
        return len(raw) == len(checked) == len(serialized) and all(
            _same_wire_value(left, middle, right)
            for left, middle, right in zip(raw, checked, serialized, strict=True)
        )
    if isinstance(raw, tuple) and isinstance(checked, tuple) and isinstance(serialized, list):
        return len(raw) == len(checked) == len(serialized) and all(
            _same_wire_value(left, middle, right)
            for left, middle, right in zip(raw, checked, serialized, strict=True)
        )
    if type(raw) is bytes:
        return type(checked) is bytes and raw == checked
    if isinstance(raw, (Enum, datetime, date, time)):
        return type(raw) is type(checked) and raw == checked
    return type(raw) is type(serialized) and raw == serialized


def _strict_rehydrate_v1(
    model: type[_ModelT],
    value: object,
    *,
    location: str,
) -> _ModelT:
    """Rebuild one model from raw state and reject coercion, cycles, and excess."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            raw = _wire_snapshot(value)
            if not isinstance(raw, dict):
                raise ValueError
            checked = model.model_validate(raw)
            checked_raw = _wire_snapshot(checked)
            serialized = checked.model_dump(mode="json", warnings="error")
            if len(canonical_json_bytes(serialized)) > _MAX_WIRE_BYTES:
                raise ValueError
            if not _same_wire_value(raw, checked_raw, serialized):
                raise ValueError
            return checked
    except Exception:
        raise ValueError(f"{location} is invalid") from None


def _validate_json_tree(value: object, *, location: str) -> object:
    if type(value) is not dict:
        raise ValueError(f"{location} must be an object")
    pending: list[tuple[object, bool]] = [(value, False)]
    active: set[int] = set()
    nodes = 0
    byte_count = 0
    while pending:
        current, exiting = pending.pop()
        if exiting:
            active.remove(id(current))
            continue
        nodes += 1
        if nodes > _MAX_WIRE_NODES:
            raise ValueError(f"{location} exceeds resource limits")
        if type(current) is str:
            byte_count += len(current.encode("utf-8"))
        else:
            byte_count += 1
        if byte_count > _MAX_WIRE_BYTES:
            raise ValueError(f"{location} exceeds resource limits")
        if type(current) is dict:
            identity = id(current)
            if identity in active:
                raise ValueError(f"{location} must not contain a cycle")
            active.add(identity)
            pending.append((current, True))
            for key, item in dict.items(current):
                if type(key) is not str:
                    raise ValueError(f"{location} keys must be strings")
                pending.append((item, False))
        elif type(current) is list:
            identity = id(current)
            if identity in active:
                raise ValueError(f"{location} must not contain a cycle")
            active.add(identity)
            pending.append((current, True))
            pending.extend((item, False) for item in current)
        elif (
            current is None
            or type(current) in {str, bool, int}
            or (type(current) is float and math.isfinite(current))
        ):
            continue
        else:
            raise ValueError(f"{location} must contain only JSON wire values")
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{location} is not canonical JSON") from error
    return value


class ReadinessStrictModelV1(BaseModel):
    """Immutable, closed values which rehydrate raw Pydantic state."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def rehydrate_raw_model_state(cls, value: object) -> object:
        return _wire_snapshot(value)

    @model_validator(mode="after")
    def freeze_nested_values(self) -> Self:
        serialized = self.model_dump(mode="json", warnings="error")
        for field_name, field_info in type(self).model_fields.items():
            value = getattr(self, field_name)
            if field_name not in serialized:
                if _is_trusted_serialization_exclusion(self, field_name):
                    continue
                raise ValueError("validated readiness model is missing serialized state")
            frozen = _freeze_validated_wire(
                value,
                serialized[field_name],
                annotation=field_info.annotation,
            )
            if frozen is not value:
                object.__setattr__(self, field_name, frozen)
        return self


class RequirementDispositionV1(StrEnum):
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    UNCERTAIN = "uncertain"


class DeliveryReadinessTierV1(StrEnum):
    HIGH_ASSURANCE = "HIGH_ASSURANCE"
    REVIEW_READY_WITH_GAPS = "REVIEW_READY_WITH_GAPS"
    NOT_DELIVERABLE = "NOT_DELIVERABLE"


class ReadinessOperationV1(StrEnum):
    BASELINE_LOCKED_GRADE = "baseline_locked_grade"
    BASELINE_LOCKED_CONTESTED_GRADE = "baseline_locked_contested_grade"
    SAFETY_REVIEW = "safety_review"
    SAFETY_REFEREE = "safety_referee"


class ReadinessPhaseV1(StrEnum):
    CREATED = "created"
    BASELINE_LOCKED_GRADE = "baseline_locked_grade"
    BASELINE_LOCKED_STRICT_EQUIVALENT = "baseline_locked_strict_equivalent"
    SAFETY_REVIEW = "safety_review"
    SAFETY_REFEREE = "safety_referee"
    COMPILE = "compile"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"


class RationaleKindV1(StrEnum):
    REPORT_OMISSION = "REPORT_OMISSION"
    REPORT_PARTIAL_TREATMENT = "REPORT_PARTIAL_TREATMENT"
    SOURCE_ABSENT = "SOURCE_ABSENT"
    SOURCE_AMBIGUOUS = "SOURCE_AMBIGUOUS"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    CURRENTNESS_NOT_ESTABLISHED = "CURRENTNESS_NOT_ESTABLISHED"
    APPLICABILITY_FACT_MISSING = "APPLICABILITY_FACT_MISSING"
    LANGUAGE_LIMITATION = "LANGUAGE_LIMITATION"
    CONTESTED_INTERPRETATION = "CONTESTED_INTERPRETATION"
    UNSUPPORTED_ASSERTION = "UNSUPPORTED_ASSERTION"
    SAFETY_REVIEW_FINDING = "SAFETY_REVIEW_FINDING"


class FollowUpCodeV1(StrEnum):
    VERIFY_PRIMARY_AUTHORITY = "VERIFY_PRIMARY_AUTHORITY"
    CONFIRM_CURRENTNESS = "CONFIRM_CURRENTNESS"
    RESOLVE_APPLICABILITY_FACT = "RESOLVE_APPLICABILITY_FACT"
    OBTAIN_OUTSIDE_COUNSEL_ANALYSIS = "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS"
    EXPAND_REQUIREMENT_ANALYSIS = "EXPAND_REQUIREMENT_ANALYSIS"
    CORRECT_UNSUPPORTED_ASSERTION = "CORRECT_UNSUPPORTED_ASSERTION"
    RESOLVE_LANGUAGE_LIMITATION = "RESOLVE_LANGUAGE_LIMITATION"
    RESOLVE_CONTESTED_INTERPRETATION = "RESOLVE_CONTESTED_INTERPRETATION"


class OwnerRoleV1(StrEnum):
    REVIEWING_ATTORNEY = "reviewing_attorney"
    OUTSIDE_COUNSEL = "outside_counsel"
    RESEARCH_OPERATOR = "research_operator"


class GapOriginV1(StrEnum):
    REQUIREMENT = "requirement"
    BASELINE_GAP = "baseline_gap"
    CONTESTED_REQUIREMENT = "contested_requirement"
    SAFETY_FINDING = "safety_finding"
    PREREQUISITE = "prerequisite"


class GapVisibilityV1(StrEnum):
    PROMINENT = "prominent"
    VISIBLE = "visible"
    HIDDEN = "hidden"


class SafetyFindingKindV1(StrEnum):
    MATERIAL_UNSUPPORTED_ASSERTION = "MATERIAL_UNSUPPORTED_ASSERTION"
    BASELINE_CONTRADICTION = "BASELINE_CONTRADICTION"
    HIDDEN_OR_UNDERSTATED_LIMITATION = "HIDDEN_OR_UNDERSTATED_LIMITATION"
    UNDISCLOSED_DISPOSITIVE_CLIENT_FACT = "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT"
    MISLEADING_CURRENTNESS_OR_AUTHORITY = "MISLEADING_CURRENTNESS_OR_AUTHORITY"
    UNDISCLOSED_GRADER_GAP = "UNDISCLOSED_GRADER_GAP"


class HistoricalV22CrossCheckStatusV1(StrEnum):
    NOT_PROVIDED = "NOT_PROVIDED"
    BASELINE_NOT_COMPARABLE = "BASELINE_NOT_COMPARABLE"
    REPORT_NOT_COMPARABLE = "REPORT_NOT_COMPARABLE"
    MATCH = "MATCH"
    DISPOSITION_DIFFERS = "DISPOSITION_DIFFERS"


_BLOCKING_CODES = (
    "INTEGRITY_OR_PROVENANCE_INVALID",
    "MINIMUM_LANE_COVERAGE_BELOW_FLOOR",
    "MATERIAL_UNSUPPORTED_ASSERTION",
    "BASELINE_CONTRADICTION",
    "HIDDEN_MATERIAL_GAP",
    "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
    "MISLEADING_CURRENTNESS_OR_AUTHORITY",
    "OUTCOME_DETERMINATIVE_CONTEST",
    "MISSING_REQUIRED_FOLLOW_UP",
    "GAP_RATIONALE_INVALID",
    "CRITICAL_DISCLOSURE_INVALID",
    "FALSE_RESOLUTION",
)
_GENERIC_RATIONALES = (
    "more research needed",
    "insufficient information",
    "requirement partially met",
)
_VERIFICATION_ISSUE_CODES = frozenset(
    {
        "INTEGRITY_OR_PROVENANCE_INVALID",
        "RATIONALE_EVIDENCE_UNBOUND",
        "READINESS_ARTIFACT_INVALID",
        "READINESS_COMPILER_INVARIANT",
        "READINESS_COMPILER_PREFLIGHT_DISAGREEMENT",
        "READINESS_INVENTORY_INVALID",
        "READINESS_MANIFEST_INVALID",
        "READINESS_RESULT_REQUIRED",
        "READINESS_SEMANTIC_REPLAY_INVALID",
        "READINESS_STORAGE_UNSAFE",
        "READINESS_VALIDATION_RECEIPT_INVALID",
    }
)


StrictImportanceWeight = Annotated[int, Field(ge=0, strict=True)]
StrictDispositionCredit = Annotated[float, Field(ge=0.0, le=1.0, strict=True)]


class ReadinessRubricV1(ReadinessStrictModelV1):
    version: Literal["delivery-readiness-v1"]
    attorney_review_warning: str = Field(strict=True)
    blocking_codes: tuple[str, ...]
    disposition_credit: dict[RequirementDispositionV1, StrictDispositionCredit]
    follow_up_codes: tuple[FollowUpCodeV1, ...]
    generic_rationales: tuple[str, ...]
    high_assurance_critical_recall_floor: float = Field(ge=0.0, le=1.0, strict=True)
    high_assurance_weighted_coverage_floor: float = Field(ge=0.0, le=1.0, strict=True)
    owner_roles: tuple[OwnerRoleV1, ...]
    rationale_kinds: tuple[RationaleKindV1, ...]
    review_ready_weighted_coverage_floor: float = Field(ge=0.0, le=1.0, strict=True)
    strict_equivalent_scoring_semantics: Literal["attorney-eval-v2.2"]
    strict_importance_weights: dict[BaselineImportanceV1, StrictImportanceWeight]

    _validate_warning = field_validator("attorney_review_warning")(_nonblank)

    @field_validator(
        "high_assurance_critical_recall_floor",
        "high_assurance_weighted_coverage_floor",
        "review_ready_weighted_coverage_floor",
        mode="before",
    )
    @classmethod
    def validate_native_floats(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("readiness rubric thresholds must be native floats")
        return value

    @field_validator("disposition_credit", mode="before")
    @classmethod
    def validate_native_credits(cls, value: object) -> object:
        if type(value) is not dict or any(
            type(item) is not float for item in cast(dict[object, object], value).values()
        ):
            raise ValueError("readiness disposition credits must be native floats")
        return value

    @field_validator("strict_importance_weights", mode="before")
    @classmethod
    def validate_native_weights(cls, value: object) -> object:
        if type(value) is not dict or any(
            type(item) is not int for item in cast(dict[object, object], value).values()
        ):
            raise ValueError("readiness importance weights must be native integers")
        return value

    @model_validator(mode="after")
    def validate_exact_policy_inventory(self) -> Self:
        expected_credits = {
            RequirementDispositionV1.MET: 1.0,
            RequirementDispositionV1.PARTIALLY_MET: 0.5,
            RequirementDispositionV1.NOT_MET: 0.0,
            RequirementDispositionV1.UNCERTAIN: 0.0,
        }
        expected_weights = {
            BaselineImportanceV1.CRITICAL: 3,
            BaselineImportanceV1.MATERIAL: 2,
            BaselineImportanceV1.SUPPORTING: 1,
        }
        if (
            dict(self.disposition_credit) != expected_credits
            or dict(self.strict_importance_weights) != expected_weights
            or self.blocking_codes != _BLOCKING_CODES
            or self.follow_up_codes != tuple(FollowUpCodeV1)
            or self.generic_rationales != _GENERIC_RATIONALES
            or self.owner_roles != tuple(OwnerRoleV1)
            or self.rationale_kinds != tuple(RationaleKindV1)
            or self.review_ready_weighted_coverage_floor != 0.7
            or self.high_assurance_weighted_coverage_floor != 0.9
            or self.high_assurance_critical_recall_floor != 1.0
        ):
            raise ValueError("readiness rubric does not match the closed v1 policy")
        return self


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("readiness rubric contains duplicate keys")
        result[key] = value
    return result


def load_readiness_rubric_v1() -> ReadinessRubricV1:
    """Load the exact packaged canonical readiness policy."""
    path = Path(__file__).with_name("readiness-rubric-v1.json")
    try:
        data = path.read_bytes()
        parsed = json.loads(data, object_pairs_hook=_reject_duplicate_json_pairs)
        if type(parsed) is not dict or canonical_json_bytes(parsed) != data:
            raise ValueError
        return ReadinessRubricV1.model_validate(parsed)
    except (OSError, TypeError, UnicodeDecodeError, ValidationError, ValueError) as error:
        raise ValueError("readiness rubric v1 is invalid") from error


class GenerationValidationBindingV1(ReadinessStrictModelV1):
    receipt_hash: Hash
    report_hash: Hash
    bundle_hash: Hash
    coverage_review_hash: Hash
    status: Literal["completed"]
    evidence_precision_valid: bool = Field(strict=True)
    proposition_coverage_valid: bool = Field(strict=True)
    provision_recall_valid: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_completed_receipt(self) -> Self:
        if not (
            self.evidence_precision_valid
            and self.proposition_coverage_valid
            and self.provision_recall_valid
        ):
            raise ValueError("generation validation binding must be deterministically complete")
        return self


class HistoricalV22CrossCheckV1(ReadinessStrictModelV1):
    report_hash: Hash
    strict_disposition: AbsoluteDispositionV2
    result_fingerprint: Hash
    manifest_fingerprint: Hash
    baseline_fingerprint: Hash
    grader_aggregate_fingerprints: tuple[Hash, ...]
    reason_codes: tuple[str, ...] = ()
    baseline_comparable: bool = Field(strict=True)
    report_comparable: bool = Field(strict=True)

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_nonblank(values, location="historical reason codes")


class ReadinessInputV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"]
    gradeable_baseline: GradeableBaselineProjectionV1
    grade_target_fingerprint: Hash
    report_text: str = Field(strict=True)
    report_hash: Hash
    generation_capsule_root: Hash
    generation_validation: GenerationValidationBindingV1
    readiness_rubric_fingerprint: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    historical_v22_cross_check: HistoricalV22CrossCheckV1 | None = None

    _validate_report = field_validator("report_text")(_preserve_nonblank)

    @model_validator(mode="after")
    def validate_input_bindings(self) -> Self:
        if (
            self.grade_target_fingerprint
            != self.gradeable_baseline.binding.grade_target_fingerprint
        ):
            raise ValueError("readiness input grade target must match its verified projection")
        if self.report_hash != self.generation_validation.report_hash:
            raise ValueError("readiness input report hash must match generation validation")
        _attest_projection(self.gradeable_baseline)
        return self


class ReadinessEvaluatorRequestV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    operation: ReadinessOperationV1
    request_fingerprint: Hash
    system_instructions: str = Field(strict=True)
    json_schema: dict[str, object]
    payload: dict[str, object]

    _validate_instructions = field_validator("system_instructions")(_preserve_nonblank)

    @field_validator("json_schema", "payload", mode="before")
    @classmethod
    def validate_wire_objects(cls, value: object) -> object:
        return _validate_json_tree(value, location="readiness request object")


class ReadinessEvaluatorResponseV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    operation: ReadinessOperationV1
    request_fingerprint: Hash
    provider_name: str = Field(strict=True)
    model_name: str = Field(strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"]
    payload: dict[str, object]

    _validate_names = field_validator("provider_name", "model_name")(_nonblank)

    @field_validator("payload", mode="before")
    @classmethod
    def validate_payload(cls, value: object) -> object:
        return _validate_json_tree(value, location="readiness response payload")


class BaselineLockedGradeBatchV1(ReadinessStrictModelV1):
    batch_ref: BatchRef
    lane: Literal[1, 2]
    requirement_ids: tuple[RequirementRef, ...] = Field(
        min_length=1,
        max_length=_MAX_FRAGMENT_ITEMS,
    )

    _validate_lane = field_validator("lane", mode="before")(_strict_lane)

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        if len(self.requirement_ids) != len(set(self.requirement_ids)):
            raise ValueError("readiness grade batch requirement IDs must be unique")
        match = re.fullmatch(_BATCH_REF_PATTERN, self.batch_ref)
        if match is None or int(match.group(0).split("-")[1]) != self.lane:
            raise ValueError("readiness grade batch reference must bind its lane")
        return self


class BaselineLockedGradeFragmentV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    lane: Literal[1, 2]
    batch_ref: BatchRef
    grade_target_fingerprint: Hash
    baseline_fingerprint: Hash
    report_hash: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    requirement_grades: tuple[RequirementGradeV2, ...] = Field(
        min_length=1,
        max_length=_MAX_FRAGMENT_ITEMS,
    )
    rationale: str = Field(strict=True)
    fragment_fingerprint: Hash

    _validate_lane = field_validator("lane", mode="before")(_strict_lane)
    _validate_passages = field_validator("requirement_grades", mode="before")(
        _validate_requirement_grade_passages
    )
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_grade_fragment(self) -> Self:
        if self.batch_ref.split("-")[1] != str(self.lane):
            raise ValueError("readiness grade fragment batch must bind its lane")
        ids = tuple(item.requirement_id for item in self.requirement_grades)
        if len(ids) != len(set(ids)):
            raise ValueError("readiness grade fragment requirement IDs must be unique")
        return self


class BaselineLockedContestedGradeV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    lane: Literal[1, 2]
    contested_requirement_id: ContestedRef
    grade_target_fingerprint: Hash
    baseline_fingerprint: Hash
    report_hash: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    reviewer_alternative_disposition: RequirementDispositionV1
    auditor_alternative_disposition: RequirementDispositionV1
    reviewer_report_passages: tuple[str, ...] = Field(max_length=_MAX_FINDINGS)
    auditor_report_passages: tuple[str, ...] = Field(max_length=_MAX_FINDINGS)
    reviewer_rationale: str = Field(strict=True)
    auditor_rationale: str = Field(strict=True)
    ambiguity_disposition: Literal["acknowledged", "overstated", "omitted", "uncertain"]
    rationale: str = Field(strict=True)
    grade_fingerprint: Hash

    _validate_lane = field_validator("lane", mode="before")(_strict_lane)
    _validate_text = field_validator(
        "reviewer_rationale",
        "auditor_rationale",
        "rationale",
    )(_nonblank)
    _validate_reviewer_passages = field_validator("reviewer_report_passages", mode="before")(
        lambda values: _unique_exact_passages(
            values,
            location="reviewer report passages",
        )
    )
    _validate_auditor_passages = field_validator("auditor_report_passages", mode="before")(
        lambda values: _unique_exact_passages(
            values,
            location="auditor report passages",
        )
    )


class BaselineLockedGraderAggregateV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    lane: Literal[1, 2]
    grade_target_fingerprint: Hash
    baseline_fingerprint: Hash
    report_hash: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    ordinary_fragments: tuple[BaselineLockedGradeFragmentV1, ...] = Field(
        max_length=_MAX_COMPILED_ITEMS
    )
    contested_grades: tuple[BaselineLockedContestedGradeV1, ...] = Field(
        max_length=_MAX_COMPILED_ITEMS
    )
    requirement_grades: tuple[RequirementGradeV2, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    aggregate_fingerprint: Hash

    _validate_lane = field_validator("lane", mode="before")(_strict_lane)
    _validate_passages = field_validator("requirement_grades", mode="before")(
        _validate_requirement_grade_passages
    )

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        expected_bindings = (
            self.lane,
            self.grade_target_fingerprint,
            self.baseline_fingerprint,
            self.report_hash,
            self.strict_equivalent_scoring_contract_fingerprint,
        )

        def bindings(
            item: BaselineLockedGradeFragmentV1 | BaselineLockedContestedGradeV1,
        ) -> tuple[int, str, str, str, str]:
            return (
                item.lane,
                item.grade_target_fingerprint,
                item.baseline_fingerprint,
                item.report_hash,
                item.strict_equivalent_scoring_contract_fingerprint,
            )

        if any(bindings(item) != expected_bindings for item in self.ordinary_fragments) or any(
            bindings(item) != expected_bindings for item in self.contested_grades
        ):
            raise ValueError("grader aggregate fragment bindings must match exactly")
        batch_refs = tuple(item.batch_ref for item in self.ordinary_fragments)
        expected_batches = tuple(
            f"GB-{self.lane}-{index:04d}" for index in range(1, len(batch_refs) + 1)
        )
        contested_ids = tuple(item.contested_requirement_id for item in self.contested_grades)
        expected_contested = tuple(
            f"CONT-{index:04d}" for index in range(1, len(contested_ids) + 1)
        )
        if batch_refs != expected_batches or contested_ids != expected_contested:
            raise ValueError("grader aggregate fragments must use exact controller order")
        flattened = tuple(
            grade for fragment in self.ordinary_fragments for grade in fragment.requirement_grades
        )
        if self.requirement_grades != flattened:
            raise ValueError("grader aggregate flattened requirement grades must match fragments")
        ids = tuple(item.requirement_id for item in self.requirement_grades)
        expected_ids = tuple(f"REQ-{index:04d}" for index in range(1, len(ids) + 1))
        if ids != expected_ids:
            raise ValueError("grader aggregate must use exact numeric requirement order")
        return self


class BaselineLockedStrictEquivalentV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    semantics: Literal["attorney-eval-v2.2-strict-equivalent"]
    absolute_disposition: AbsoluteDispositionV2
    grader_lanes: tuple[
        BaselineLockedGraderAggregateV1,
        BaselineLockedGraderAggregateV1,
    ]
    lane_critical_recall: tuple[float, float]
    lane_weighted_coverage: tuple[float, float]
    reason_codes: tuple[str, ...]
    outcome_determinative_contested_ids: tuple[str, ...] = ()
    strict_equivalent_fingerprint: Hash

    @field_validator("lane_critical_recall", "lane_weighted_coverage", mode="before")
    @classmethod
    def validate_scores(cls, value: object) -> object:
        items = cast(tuple[object, ...] | list[object], value)
        if (
            type(value) not in {tuple, list}
            or len(items) != 2
            or any(type(item) is not float or not 0.0 <= item <= 1.0 for item in items)
        ):
            raise ValueError("strict-equivalent lane scores must be two native floats")
        return value

    @field_validator("reason_codes", "outcome_determinative_contested_ids")
    @classmethod
    def validate_string_inventories(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _unique_nonblank(values, location="strict-equivalent string inventory")

    @model_validator(mode="after")
    def validate_lane_order(self) -> Self:
        if tuple(item.lane for item in self.grader_lanes) != (1, 2):
            raise ValueError("strict-equivalent grader lanes must use order 1, 2")
        return self


class SafetyGapCandidateV1(ReadinessStrictModelV1):
    candidate_id: GapCandidateRef
    canonical_order: int = Field(ge=0, strict=True)
    origin: GapOriginV1
    subject_id: str = Field(strict=True)
    importance: BaselineImportanceV1
    lane_1_disposition: RequirementDispositionV1 | None = None
    lane_2_disposition: RequirementDispositionV1 | None = None
    baseline_fingerprint: Hash
    report_hash: Hash
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(max_length=_MAX_FINDINGS)
    candidate_fingerprint: Hash

    _validate_subject = field_validator("subject_id")(_nonblank)
    _validate_evidence = field_validator("evidence_refs", mode="before")(
        lambda values: _unique_evidence_refs(values, location="candidate evidence references")
    )


class SafetyGapAssessmentV1(ReadinessStrictModelV1):
    candidate_id: GapCandidateRef
    shortfall_description: str = Field(strict=True)
    rationale_kind: RationaleKindV1
    why_unresolved: str = Field(strict=True)
    why_it_matters: str = Field(strict=True)
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(max_length=_MAX_FINDINGS)
    report_passages: tuple[str, ...] = ()
    disclosure_location: str | None = Field(default=None, strict=True)
    visibility: GapVisibilityV1
    blocking_code: str | None = Field(default=None, strict=True)
    follow_up_code: FollowUpCodeV1
    resolution_test: str = Field(strict=True)
    owner_role: OwnerRoleV1

    _validate_required_text = field_validator(
        "shortfall_description",
        "why_unresolved",
        "why_it_matters",
        "resolution_test",
    )(_nonblank)
    _validate_optional_text = field_validator("disclosure_location", "blocking_code")(
        _optional_nonblank
    )
    _validate_evidence = field_validator("evidence_refs", mode="before")(
        lambda values: _unique_evidence_refs(values, location="assessment evidence references")
    )
    _validate_passages = field_validator("report_passages", mode="before")(
        lambda values: _unique_exact_passages(
            values,
            location="assessment report passages",
        )
    )


class SafetyFindingProposalV1(ReadinessStrictModelV1):
    finding_kind: SafetyFindingKindV1
    subject_id: str = Field(strict=True)
    report_passages: tuple[str, ...] = ()
    shortfall_description: str = Field(strict=True)
    rationale_kind: RationaleKindV1
    why_unresolved: str = Field(strict=True)
    why_it_matters: str = Field(strict=True)
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(max_length=_MAX_FINDINGS)
    disclosure_location: str | None = Field(default=None, strict=True)
    visibility: GapVisibilityV1
    blocking_code: str | None = Field(default=None, strict=True)
    follow_up_code: FollowUpCodeV1
    resolution_test: str = Field(strict=True)
    owner_role: OwnerRoleV1

    _validate_required_text = field_validator(
        "subject_id",
        "shortfall_description",
        "why_unresolved",
        "why_it_matters",
        "resolution_test",
    )(_nonblank)
    _validate_optional_text = field_validator("disclosure_location", "blocking_code")(
        _optional_nonblank
    )
    _validate_evidence = field_validator("evidence_refs", mode="before")(
        lambda values: _unique_evidence_refs(values, location="finding evidence references")
    )
    _validate_passages = field_validator("report_passages", mode="before")(
        lambda values: _unique_exact_passages(
            values,
            location="finding report passages",
        )
    )


class SafetyLaneResponseV1(ReadinessStrictModelV1):
    """Evaluator-authored safety content without controller IDs or fingerprints."""

    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    lane: Literal[1, 2]
    candidate_assessments: tuple[SafetyGapAssessmentV1, ...] = Field(max_length=_MAX_FINDINGS)
    finding_proposals: tuple[SafetyFindingProposalV1, ...] = Field(max_length=_MAX_FINDINGS)

    _validate_lane = field_validator("lane", mode="before")(_strict_lane)

    @model_validator(mode="after")
    def validate_candidate_coverage_shape(self) -> Self:
        ids = tuple(item.candidate_id for item in self.candidate_assessments)
        if len(ids) != len(set(ids)):
            raise ValueError("safety lane candidate IDs must be unique")
        return self


_SafetyDisputeKindV1 = Literal[
    "finding_existence",
    "rationale",
    "evidence_binding",
    "visibility",
    "blocker",
    "follow_up",
    "owner",
    "resolution_test",
]

_DISPUTE_CHOICE_KEYS: dict[str, frozenset[str]] = {
    "finding_existence": frozenset({"present"}),
    "rationale": frozenset(
        {"shortfall_description", "rationale_kind", "why_unresolved", "why_it_matters"}
    ),
    "evidence_binding": frozenset({"evidence_refs", "report_passages"}),
    "visibility": frozenset({"disclosure_location", "visibility"}),
    "blocker": frozenset({"blocking_code"}),
    "follow_up": frozenset({"follow_up_code"}),
    "owner": frozenset({"owner_role"}),
    "resolution_test": frozenset({"resolution_test"}),
}


def _choice_nonblank(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _validate_dispute_choice(kind: str, choice: dict[str, object]) -> None:
    if set(choice) != _DISPUTE_CHOICE_KEYS[kind]:
        raise ValueError("safety dispute choice has fields outside its disputed dimension")
    if kind == "finding_existence":
        valid = type(choice["present"]) is bool and choice["present"] is True
    elif kind == "rationale":
        valid = (
            _choice_nonblank(choice["shortfall_description"])
            and choice["rationale_kind"] in {item.value for item in RationaleKindV1}
            and _choice_nonblank(choice["why_unresolved"])
            and _choice_nonblank(choice["why_it_matters"])
        )
    elif kind == "evidence_binding":
        evidence = choice["evidence_refs"]
        passages = choice["report_passages"]
        if type(evidence) is _FrozenJsonList:
            evidence = list(evidence)
        if type(passages) is _FrozenJsonList:
            passages = list(passages)
        _unique_evidence_refs(
            evidence,
            location="dispute choice evidence references",
        )
        _unique_exact_passages(
            passages,
            location="dispute choice report passages",
        )
        valid = True
    elif kind == "visibility":
        location = choice["disclosure_location"]
        valid = (location is None or _choice_nonblank(location)) and choice["visibility"] in {
            item.value for item in GapVisibilityV1
        }
    elif kind == "blocker":
        blocker = choice["blocking_code"]
        valid = blocker is None or _choice_nonblank(blocker)
    elif kind == "follow_up":
        valid = choice["follow_up_code"] in {item.value for item in FollowUpCodeV1}
    elif kind == "owner":
        valid = choice["owner_role"] in {item.value for item in OwnerRoleV1}
    else:
        valid = _choice_nonblank(choice["resolution_test"])
    if not valid:
        raise ValueError("safety dispute choice has an invalid dimension value")


class SafetyDisputeV1(ReadinessStrictModelV1):
    dispute_id: SafetyDisputeRef
    canonical_order: int = Field(ge=0, lt=_MAX_FINDINGS, strict=True)
    dispute_kind: _SafetyDisputeKindV1
    subject_identity: str = Field(max_length=_MAX_EVIDENCE_REF_LENGTH, strict=True)
    lane_1_choice: dict[str, object] | None
    lane_2_choice: dict[str, object] | None
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(max_length=_MAX_FINDINGS)
    report_passages: tuple[str, ...] = Field(max_length=_MAX_FINDINGS)
    grade_target_fingerprint: Hash
    baseline_fingerprint: Hash
    report_hash: Hash
    dispute_fingerprint: Hash

    _validate_subject = field_validator("subject_identity")(_nonblank)
    _validate_evidence = field_validator("evidence_refs", mode="before")(
        lambda values: _unique_evidence_refs(values, location="dispute evidence references")
    )
    _validate_passages = field_validator("report_passages", mode="before")(
        lambda values: _unique_exact_passages(values, location="dispute report passages")
    )

    @field_validator("lane_1_choice", "lane_2_choice", mode="before")
    @classmethod
    def validate_choice_tree(cls, value: object) -> object:
        if value is None:
            return None
        return _validate_json_tree(value, location="safety dispute choice")

    @model_validator(mode="after")
    def validate_dispute(self) -> Self:
        if int(self.dispute_id.split("-")[1]) != self.canonical_order + 1:
            raise ValueError("safety dispute ID must bind its canonical order")
        first = self.lane_1_choice
        second = self.lane_2_choice
        if self.dispute_kind == "finding_existence":
            if (first is None) == (second is None):
                raise ValueError("finding-existence disputes require exactly one absent choice")
        elif first is None or second is None:
            raise ValueError("nonexistence is valid only for finding-existence disputes")
        for choice in (first, second):
            if choice is not None:
                _validate_dispute_choice(self.dispute_kind, choice)
        if canonical_json_bytes(first) == canonical_json_bytes(second):
            raise ValueError("safety dispute choices must differ")
        if self.dispute_kind == "evidence_binding":
            if first is None or second is None:
                raise ValueError("evidence-binding disputes require two choices")
            expected_evidence = tuple(
                dict.fromkeys(
                    cast(list[str], first["evidence_refs"])
                    + cast(list[str], second["evidence_refs"])
                )
            )
            expected_passages = tuple(
                dict.fromkeys(
                    cast(list[str], first["report_passages"])
                    + cast(list[str], second["report_passages"])
                )
            )
            if self.evidence_refs != expected_evidence or self.report_passages != expected_passages:
                raise ValueError("evidence-binding dispute scope must match its two choices")
        return self


class SafetyRefereeDecisionV1(ReadinessStrictModelV1):
    dispute_id: SafetyDisputeRef
    disposition: Literal["lane_1", "lane_2", "blocking", "unresolved"]
    rationale: str = Field(strict=True)
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(max_length=_MAX_FINDINGS)

    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_evidence = field_validator("evidence_refs", mode="before")(
        lambda values: _unique_evidence_refs(values, location="referee evidence references")
    )


class ReconciledSafetyReviewV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    candidate_assessments: tuple[SafetyGapAssessmentV1, ...]
    finding_proposals: tuple[SafetyFindingProposalV1, ...]
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...] = ()
    blocking_codes: tuple[str, ...]
    safety_review_fingerprint: Hash

    @model_validator(mode="after")
    def validate_reconciled_inventory(self) -> Self:
        candidate_ids = tuple(item.candidate_id for item in self.candidate_assessments)
        dispute_ids = tuple(item.dispute_id for item in self.referee_decisions)
        if len(candidate_ids) != len(set(candidate_ids)) or len(dispute_ids) != len(
            set(dispute_ids)
        ):
            raise ValueError("reconciled safety controller IDs must be unique")
        _unique_nonblank(self.blocking_codes, location="safety blocking codes")
        return self


class RequirementMatrixRowV1(ReadinessStrictModelV1):
    requirement_id: RequirementRef
    canonical_order: int = Field(ge=0, strict=True)
    statement: str = Field(strict=True)
    kind: str = Field(strict=True)
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...]
    importance_rationale: str = Field(strict=True)
    lane_1_disposition: RequirementDispositionV1
    lane_2_disposition: RequirementDispositionV1
    conservative_disposition: RequirementDispositionV1
    lane_1_report_passages: tuple[str, ...] = ()
    lane_2_report_passages: tuple[str, ...] = ()
    row_fingerprint: Hash

    _validate_text = field_validator("statement", "kind")(_nonblank)
    _validate_passages = field_validator(
        "lane_1_report_passages",
        "lane_2_report_passages",
        mode="before",
    )(
        lambda values: _unique_exact_passages(
            values,
            location="requirement matrix report passages",
        )
    )

    @model_validator(mode="after")
    def validate_importance_contract(self) -> Self:
        validate_importance_rationale_v1(
            self.importance,
            self.importance_basis,
            self.importance_rationale,
        )
        return self


class RequirementMatrixV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    grade_target_fingerprint: Hash
    report_hash: Hash
    rows: tuple[RequirementMatrixRowV1, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    matrix_fingerprint: Hash

    @model_validator(mode="after")
    def validate_rows(self) -> Self:
        ids = tuple(item.requirement_id for item in self.rows)
        orders = tuple(item.canonical_order for item in self.rows)
        if len(ids) != len(set(ids)) or orders != tuple(range(len(self.rows))):
            raise ValueError("requirement matrix rows must use unique IDs and contiguous order")
        return self


class GapFollowUpRowV1(ReadinessStrictModelV1):
    gap_id: GapRef
    canonical_order: int = Field(ge=0, strict=True)
    origin: GapOriginV1
    subject_id: str = Field(strict=True)
    kind: str = Field(strict=True)
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...]
    importance_rationale: str = Field(strict=True)
    lane_1_disposition: RequirementDispositionV1 | None = None
    lane_2_disposition: RequirementDispositionV1 | None = None
    conservative_disposition: RequirementDispositionV1 | None = None
    report_passages: tuple[str, ...] = ()
    shortfall_description: str = Field(strict=True)
    rationale_kind: RationaleKindV1
    why_unresolved: str = Field(strict=True)
    why_it_matters: str = Field(strict=True)
    evidence_refs: tuple[str, ...]
    disclosure_location: str | None = Field(default=None, strict=True)
    visibility: GapVisibilityV1
    blocking_code: str | None = Field(default=None, strict=True)
    follow_up_code: FollowUpCodeV1
    resolution_test: str = Field(strict=True)
    owner_role: OwnerRoleV1
    status: Literal["open", "resolved"]
    referee_dispute_id: str | None = Field(default=None, strict=True)
    row_fingerprint: Hash

    _validate_required_text = field_validator(
        "subject_id",
        "kind",
        "shortfall_description",
        "why_unresolved",
        "why_it_matters",
        "resolution_test",
    )(_nonblank)
    _validate_optional_text = field_validator(
        "disclosure_location",
        "blocking_code",
        "referee_dispute_id",
    )(_optional_nonblank)
    _validate_passages = field_validator("report_passages", mode="before")(
        lambda values: _unique_exact_passages(
            values,
            location="gap report passages",
        )
    )
    _validate_evidence = field_validator("evidence_refs")(
        lambda values: _unique_nonblank(values, location="gap evidence references")
    )

    @model_validator(mode="after")
    def validate_importance_contract(self) -> Self:
        validate_importance_rationale_v1(
            self.importance,
            self.importance_basis,
            self.importance_rationale,
        )
        return self


class GapFollowUpMatrixV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    grade_target_fingerprint: Hash
    report_hash: Hash
    rows: tuple[GapFollowUpRowV1, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    matrix_fingerprint: Hash

    @model_validator(mode="after")
    def validate_rows(self) -> Self:
        ids = tuple(item.gap_id for item in self.rows)
        orders = tuple(item.canonical_order for item in self.rows)
        expected_ids = tuple(f"GAP-{index:04d}" for index in range(1, len(self.rows) + 1))
        if ids != expected_ids or orders != tuple(range(len(self.rows))):
            raise ValueError("gap matrix rows must use contiguous controller IDs and order")
        return self


class DeliveryReadinessResultV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"]
    baseline_locked_strict_equivalent_disposition: AbsoluteDispositionV2
    historical_v22_strict_disposition: AbsoluteDispositionV2 | None
    historical_v22_cross_check_status: HistoricalV22CrossCheckStatusV1
    delivery_readiness: DeliveryReadinessTierV1
    minimum_lane_weighted_coverage: float = Field(ge=0.0, le=1.0, strict=True)
    lane_critical_recall: tuple[float, float]
    lane_weighted_coverage: tuple[float, float]
    requirement_matrix_fingerprint: Hash
    gap_matrix_fingerprint: Hash
    blocking_codes: tuple[str, ...]
    attorney_review_warning: str = Field(strict=True)
    result_fingerprint: Hash

    _validate_warning = field_validator("attorney_review_warning")(_nonblank)

    @field_validator("minimum_lane_weighted_coverage", mode="before")
    @classmethod
    def validate_minimum_score(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("minimum lane weighted coverage must be a native float")
        return value

    @field_validator("lane_critical_recall", "lane_weighted_coverage", mode="before")
    @classmethod
    def validate_lane_scores(cls, value: object) -> object:
        items = cast(tuple[object, ...] | list[object], value)
        if (
            type(value) not in {tuple, list}
            or len(items) != 2
            or any(type(item) is not float or not 0.0 <= item <= 1.0 for item in items)
        ):
            raise ValueError("lane scores must contain exactly two native floats")
        return value

    @field_validator("blocking_codes")
    @classmethod
    def validate_blocking_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        checked = _unique_nonblank(values, location="result blocking codes")
        if any(value not in _BLOCKING_CODES for value in checked):
            raise ValueError("result blocking codes must use the readiness rubric inventory")
        return checked

    @model_validator(mode="after")
    def validate_historical_status(self) -> Self:
        provided = self.historical_v22_strict_disposition is not None
        if provided != (
            self.historical_v22_cross_check_status
            is not HistoricalV22CrossCheckStatusV1.NOT_PROVIDED
        ):
            raise ValueError("historical disposition and cross-check status must agree")
        return self


class ReadinessCallRecordV1(ReadinessStrictModelV1):
    call_id: str = Field(strict=True)
    operation: ReadinessOperationV1
    state: Literal["pending", "accepted"]
    attempt: Literal[1, 2]
    lane: Literal[1, 2] | None = None
    request_artifact_path: str = Field(strict=True)
    request_fingerprint: Hash
    response_artifact_path: str | None = Field(default=None, strict=True)
    response_fingerprint: Hash | None = None
    provider_name: str | None = Field(default=None, strict=True)
    model_name: str | None = Field(default=None, strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"] | None = None
    context_token_fingerprint: Hash | None = None
    dispute_id: SafetyDisputeRef | None = None

    _validate_attempt = field_validator("attempt", mode="before")(_strict_attempt)
    _validate_lane = field_validator("lane", mode="before")(
        lambda value: None if value is None else _strict_lane(value)
    )
    _validate_required_text = field_validator("call_id", "request_artifact_path")(_nonblank)
    _validate_optional_text = field_validator(
        "response_artifact_path",
        "provider_name",
        "model_name",
    )(_optional_nonblank)

    @model_serializer(mode="wrap")
    def serialize_call(
        self,
        handler: SerializerFunctionWrapHandler,
    ) -> dict[str, object]:
        serialized = cast(dict[str, object], handler(self))
        if self.context_token_fingerprint is None:
            serialized.pop("context_token_fingerprint", None)
        return serialized

    @field_validator("context_token_fingerprint", mode="before")
    @classmethod
    def validate_context_token_fingerprint(cls, value: object) -> object:
        if value is not None and type(value) is not str:
            raise ValueError("context token fingerprint must be a native hash")
        return value

    @model_validator(mode="after")
    def validate_call(self) -> Self:
        provenance = (
            self.response_artifact_path,
            self.response_fingerprint,
            self.provider_name,
            self.model_name,
            self.judge_isolation,
        )
        if self.state == "pending" and (
            any(item is not None for item in provenance)
            or self.context_token_fingerprint is not None
        ):
            raise ValueError("pending readiness calls must omit response provenance")
        if self.state == "accepted" and any(item is None for item in provenance):
            raise ValueError("accepted readiness calls require complete response provenance")
        if self.context_token_fingerprint is not None and self.judge_isolation != "fresh_context":
            raise ValueError("scripted fixture calls must omit context token provenance")
        if self.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
            expected = rf"grade-lane-{self.lane}-GB-{self.lane}-[0-9]{{4}}"
            if (
                self.lane is None
                or self.dispute_id is not None
                or re.fullmatch(expected, self.call_id) is None
            ):
                raise ValueError("ordinary grade calls must bind one lane and batch")
        elif self.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
            expected = rf"contested-grade-lane-{self.lane}-CONT-[0-9]{{4}}"
            if (
                self.lane is None
                or self.dispute_id is not None
                or re.fullmatch(expected, self.call_id) is None
            ):
                raise ValueError("contested grade calls must bind one lane and subject")
        elif self.operation is ReadinessOperationV1.SAFETY_REVIEW:
            if (
                self.lane is None
                or self.dispute_id is not None
                or self.call_id != f"safety-lane-{self.lane}"
            ):
                raise ValueError("safety review calls must bind one lane")
        elif (
            self.lane is not None
            or self.dispute_id is None
            or self.call_id != f"safety-referee-{self.dispute_id}"
        ):
            raise ValueError("safety referee calls must bind one dispute")
        if self.request_artifact_path != f"requests/{self.call_id}.json":
            raise ValueError("readiness request path must match its call ID")
        if self.state == "accepted" and self.response_artifact_path != (
            f"responses/{self.call_id}.json"
        ):
            raise ValueError("readiness response path must match its call ID")
        return self


class _ImmutableArtifactRecordV1(ArtifactRecord):
    """Wire-compatible detached artifact record owned by a readiness manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def snapshot_artifact(cls, value: object) -> object:
        return _wire_snapshot(value)


class ReadinessManifestV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    grade_target_fingerprint: Hash
    report_hash: Hash
    generation_capsule_root: Hash
    readiness_rubric_fingerprint: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    phase: ReadinessPhaseV1
    terminal_status: Literal["COMPLETED", "INCONCLUSIVE"] | None = None
    pending_call: ReadinessCallRecordV1 | None = None
    accepted_calls: tuple[ReadinessCallRecordV1, ...] = ()
    baseline_locked_strict_equivalent_fingerprint: Hash | None = None
    safety_review_fingerprint: Hash | None = None
    requirement_matrix_fingerprint: Hash | None = None
    gap_matrix_fingerprint: Hash | None = None
    result_fingerprint: Hash | None = None
    artifacts: tuple[_ImmutableArtifactRecordV1, ...]
    root_hash: Hash
    manifest_fingerprint: Hash

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        expected = {
            ReadinessPhaseV1.COMPLETED: "COMPLETED",
            ReadinessPhaseV1.INCONCLUSIVE: "INCONCLUSIVE",
        }.get(self.phase)
        if self.terminal_status != expected:
            raise ValueError("terminal readiness phase and status must match exactly")
        if expected is not None and self.pending_call is not None:
            raise ValueError("terminal readiness manifests must not retain a pending call")
        if self.pending_call is not None and self.pending_call.state != "pending":
            raise ValueError("pending_call must contain one pending readiness call")
        if any(call.state != "accepted" for call in self.accepted_calls):
            raise ValueError("accepted_calls must contain only accepted readiness calls")
        calls = (*self.accepted_calls, *((self.pending_call,) if self.pending_call else ()))
        call_ids = tuple(call.call_id for call in calls)
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("readiness call IDs must be unique")
        paths = tuple(artifact.artifact_path for artifact in self.artifacts)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("readiness artifacts must be uniquely path-sorted")
        return self


class ReadinessRunStateV1(ReadinessStrictModelV1):
    schema_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    grade_target_fingerprint: Hash
    report_hash: Hash
    phase: ReadinessPhaseV1
    current_call_id: str | None = Field(default=None, strict=True)
    terminal_status: Literal["COMPLETED", "INCONCLUSIVE"] | None = None
    manifest_fingerprint: Hash | None = None

    _validate_call = field_validator("current_call_id")(_safe_call_id)

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        expected = {
            ReadinessPhaseV1.COMPLETED: "COMPLETED",
            ReadinessPhaseV1.INCONCLUSIVE: "INCONCLUSIVE",
        }.get(self.phase)
        if self.terminal_status != expected:
            raise ValueError("terminal readiness phase and state must match exactly")
        if expected is not None and self.current_call_id is not None:
            raise ValueError("terminal readiness state must not retain a current call")
        return self


class ReadinessVerificationV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"] = READINESS_PROTOCOL_V1
    valid: bool = Field(strict=True)
    checks: dict[
        Literal[
            "baseline_valid",
            "evaluation_valid",
            "full_parity_valid",
            "generation_valid",
            "integrity_valid",
            "parity_contract_valid",
            "portable_parity_valid",
            "provenance_valid",
            "qualification_valid",
            "readiness_valid",
            "replay_valid",
            "storage_valid",
        ],
        Annotated[bool, Field(strict=True)],
    ] = {}
    issues: tuple[str, ...] = ()
    graph_fingerprint: Hash | None = None
    verification_fingerprint: Hash | None = None

    @field_validator("checks", mode="before")
    @classmethod
    def validate_checks(cls, value: object) -> object:
        if type(value) is not dict or any(
            type(item) is not bool for item in cast(dict[object, object], value).values()
        ):
            raise ValueError("readiness verification checks must be native booleans")
        if tuple(cast(dict[str, object], value)) != tuple(sorted(cast(dict[str, object], value))):
            raise ValueError("readiness verification checks must be key-sorted")
        return value

    @field_validator("issues")
    @classmethod
    def validate_issues(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(_nonblank(value) for value in values)
        if any(value not in _VERIFICATION_ISSUE_CODES for value in checked):
            raise ValueError("readiness verification issues must use the reviewed inventory")
        if checked != tuple(sorted(set(checked))):
            raise ValueError("readiness verification issues must be sorted and unique")
        return checked

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.valid != (not self.issues and all(self.checks.values())):
            raise ValueError("readiness verification validity must match checks and issues")
        return self


def validate_readiness_input_v1(value: object) -> ReadinessInputV1:
    return _strict_rehydrate_v1(ReadinessInputV1, value, location="readiness input")


def validate_readiness_evaluator_request_v1(value: object) -> ReadinessEvaluatorRequestV1:
    return _strict_rehydrate_v1(
        ReadinessEvaluatorRequestV1,
        value,
        location="readiness evaluator request",
    )


def validate_readiness_evaluator_response_v1(value: object) -> ReadinessEvaluatorResponseV1:
    return _strict_rehydrate_v1(
        ReadinessEvaluatorResponseV1,
        value,
        location="readiness evaluator response",
    )


def validate_readiness_result_v1(value: object) -> DeliveryReadinessResultV1:
    return _strict_rehydrate_v1(
        DeliveryReadinessResultV1,
        value,
        location="delivery readiness result",
    )


def validate_readiness_manifest_v1(value: object) -> ReadinessManifestV1:
    return _strict_rehydrate_v1(
        ReadinessManifestV1,
        value,
        location="readiness manifest",
    )


def validate_readiness_run_state_v1(value: object) -> ReadinessRunStateV1:
    return _strict_rehydrate_v1(
        ReadinessRunStateV1,
        value,
        location="readiness run state",
    )


def validate_readiness_verification_v1(value: object) -> ReadinessVerificationV1:
    return _strict_rehydrate_v1(
        ReadinessVerificationV1,
        value,
        location="readiness verification",
    )
