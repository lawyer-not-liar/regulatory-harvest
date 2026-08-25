"""Qualification-bound, report-independent identity for evaluation-baseline-v1."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, cast

from pydantic import ConfigDict, ValidationError

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_artifacts import (
    EvaluationIntegrityError,
    _open_run_storage,
    _parse_json_bytes,
    _validate_relative_path,
)
from .attorney_baseline_models import (
    BaselineInputV1,
    BaselineReuseDecisionV1,
)
from .attorney_baseline_requests import (
    BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    BASELINE_COMPILER_CONTRACT_V1,
)
from .attorney_models import ReadinessStatus
from .attorney_qualification import load_verified_qualification_context
from .attorney_v22_compiler import RUBRIC_V22

_POLICY_PATH = Path(__file__).resolve().parents[3] / "assets" / "evaluation-baseline-policy-v1.json"


class BaselineInputError(ValueError):
    """Public-safe refusal at the external baseline-input boundary."""


class BaselineControlInputV1(StrictModel):
    """Resolved controller-only paths; this value is never persisted in a baseline run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    qualification_capsule_path: Path
    client_facts_path: Path | None


def _lexical_absolute(path: Path) -> Path:
    try:
        return Path(os.path.abspath(path.expanduser()))
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise BaselineInputError("BASELINE_CONTROL_PATH_UNSAFE") from error


def _physical_file(path: Path, *, code: str) -> Path:
    lexical = _lexical_absolute(path)
    try:
        physical = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BaselineInputError(code) from error
    if lexical != physical or not physical.is_file():
        raise BaselineInputError(code)
    return physical


def _physical_relative(
    base: Path,
    value: object,
    *,
    directory: bool,
) -> Path:
    if type(value) is not str:
        raise BaselineInputError("BASELINE_CONTROL_INVALID")
    try:
        relative = _validate_relative_path(value)
    except (EvaluationIntegrityError, TypeError, ValueError) as error:
        raise BaselineInputError("BASELINE_CONTROL_PATH_UNSAFE") from error
    lexical = _lexical_absolute(base.joinpath(*relative.parts))
    try:
        physical = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BaselineInputError("BASELINE_CONTROL_PATH_UNSAFE") from error
    expected_kind = physical.is_dir() if directory else physical.is_file()
    if lexical != physical or not physical.is_relative_to(base) or not expected_kind:
        raise BaselineInputError("BASELINE_CONTROL_PATH_UNSAFE")
    return physical


def _read_physical_file(path: Path, *, code: str) -> bytes:
    try:
        with _open_run_storage(path.parent) as storage:
            return storage.read_artifact(path.name)
    except EvaluationIntegrityError as error:
        raise BaselineInputError(code) from error


def load_baseline_control_input_v1(path: Path) -> BaselineControlInputV1:
    """Load the canonical template shape and resolve paths without following aliases."""
    control_path = _physical_file(path, code="BASELINE_CONTROL_PATH_UNSAFE")
    try:
        control_bytes = _read_physical_file(
            control_path,
            code="BASELINE_CONTROL_INVALID",
        )
        if control_bytes.endswith(b"\n"):
            control_bytes = control_bytes[:-1]
        raw = _parse_json_bytes(
            control_bytes,
            location="baseline control input",
        )
    except EvaluationIntegrityError as error:
        raise BaselineInputError("BASELINE_CONTROL_INVALID") from error
    if type(raw) is not dict or set(raw) != {
        "schema_version",
        "qualification_capsule_path",
        "client_facts_path",
    }:
        raise BaselineInputError("BASELINE_CONTROL_INVALID")
    if raw["schema_version"] != "1.0":
        raise BaselineInputError("BASELINE_CONTROL_INVALID")
    base = control_path.parent
    qualification_path = _physical_relative(
        base,
        raw["qualification_capsule_path"],
        directory=True,
    )
    facts_value = raw["client_facts_path"]
    facts_path = (
        None
        if facts_value is None
        else _physical_relative(base, facts_value, directory=False)
    )
    try:
        return BaselineControlInputV1(
            qualification_capsule_path=qualification_path,
            client_facts_path=facts_path,
        )
    except ValidationError as error:
        raise BaselineInputError("BASELINE_CONTROL_INVALID") from error


def _read_exact_optional_utf8(path: Path | None) -> str | None:
    if path is None:
        return None
    data = _read_physical_file(path, code="BASELINE_CLIENT_FACTS_INVALID")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BaselineInputError("BASELINE_CLIENT_FACTS_INVALID") from error


def _canonical_v22_rubric_bytes() -> bytes:
    return canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))


def _baseline_policy_bytes() -> bytes:
    return _POLICY_PATH.read_bytes()


def _legal_input_projection_v1(value: BaselineInputV1) -> dict[str, object]:
    """Spell out every identity-bound field; do not project arbitrary model state."""
    return {
        "schema_version": value.schema_version,
        "sources": [source.model_dump(mode="json") for source in value.sources],
        "source_record_fingerprint": value.source_record_fingerprint,
        "question": value.question,
        "jurisdiction": value.jurisdiction,
        "as_of": value.as_of,
        "requested_authorities": [
            authority.model_dump(mode="json") for authority in value.requested_authorities
        ],
        "client_facts": value.client_facts,
        "client_facts_binding": value.client_facts_binding,
        "qualification_root": value.qualification_root,
        "qualification_receipt_fingerprint": value.qualification_receipt_fingerprint,
        "qualification_readiness": value.qualification_readiness,
        "compiler_contract": json.loads(canonical_json_bytes(value.compiler_contract)),
        "compiler_contract_fingerprint": value.compiler_contract_fingerprint,
        "evaluation_rubric_version": value.evaluation_rubric_version,
        "evaluation_rubric_bytes_hex": value.evaluation_rubric_bytes.hex(),
        "evaluation_rubric_fingerprint": value.evaluation_rubric_fingerprint,
        "importance_policy_version": value.importance_policy_version,
        "importance_policy_bytes_hex": value.importance_policy_bytes.hex(),
        "importance_policy_fingerprint": value.importance_policy_fingerprint,
    }


def _strict_input(value: BaselineInputV1) -> BaselineInputV1:
    try:
        raw = value.model_dump(mode="python")
        raw["compiler_contract"] = json.loads(canonical_json_bytes(raw["compiler_contract"]))
        return BaselineInputV1.model_validate(raw)
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise BaselineInputError("BASELINE_INPUT_INVALID") from error


def legal_input_fingerprint_v1(value: BaselineInputV1) -> str:
    """Hash only the explicit, report-free legal input projection."""
    checked = _strict_input(value)
    return sha256_digest(canonical_json_bytes(_legal_input_projection_v1(checked)))


def build_baseline_input_v1(control_path: Path) -> BaselineInputV1:
    """Build a canonical baseline input from one physically verified qualification."""
    control = load_baseline_control_input_v1(control_path)
    try:
        qualification = load_verified_qualification_context(
            control.qualification_capsule_path
        )
    except EvaluationIntegrityError as error:
        raise BaselineInputError("BASELINE_QUALIFICATION_INVALID") from error
    if qualification.receipt.readiness.status is not ReadinessStatus.ADMITTED:
        raise BaselineInputError("BASELINE_QUALIFICATION_NOT_ADMITTED")
    client_facts = _read_exact_optional_utf8(control.client_facts_path)
    try:
        result = BaselineInputV1.from_verified_qualification(
            qualification,
            client_facts=client_facts,
            compiler_contract=BASELINE_COMPILER_CONTRACT_V1,
            evaluation_rubric=_canonical_v22_rubric_bytes(),
            importance_policy=_baseline_policy_bytes(),
        )
    except ValueError as error:
        raise BaselineInputError("BASELINE_INPUT_INVALID") from error
    if (
        result.compiler_contract_fingerprint
        != BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1
    ):
        raise BaselineInputError("BASELINE_COMPILER_INVALID")
    return result


def baseline_reuse_decision_v1(
    sealed: BaselineInputV1,
    proposed: BaselineInputV1,
) -> BaselineReuseDecisionV1:
    """Compare named legal bindings, then prove both declared fingerprints."""
    sealed = _strict_input(sealed)
    proposed = _strict_input(proposed)
    reasons: set[str] = set()

    sealed_ids = tuple(source.source_id for source in sealed.sources)
    proposed_ids = tuple(source.source_id for source in proposed.sources)
    question_changed = sealed.question != proposed.question
    jurisdiction_changed = sealed.jurisdiction != proposed.jurisdiction
    as_of_changed = sealed.as_of != proposed.as_of
    authority_changed = sealed.requested_authorities != proposed.requested_authorities
    if sealed_ids != proposed_ids:
        reasons.add("SOURCE_ID_CHANGED")
    elif sealed.sources != proposed.sources or (
        sealed.source_record_fingerprint != proposed.source_record_fingerprint
        and not any(
            (question_changed, jurisdiction_changed, as_of_changed, authority_changed)
        )
    ):
        reasons.add("SOURCE_BYTES_CHANGED")
    if question_changed:
        reasons.add("QUESTION_CHANGED")
    if jurisdiction_changed:
        reasons.add("JURISDICTION_CHANGED")
    if as_of_changed:
        reasons.add("AS_OF_CHANGED")
    if sealed_ids == proposed_ids and authority_changed:
        reasons.add("AUTHORITY_SCOPE_CHANGED")
    if (
        sealed.client_facts != proposed.client_facts
        or sealed.client_facts_binding != proposed.client_facts_binding
    ):
        reasons.add("CLIENT_FACTS_CHANGED")
    if (
        sealed.qualification_root != proposed.qualification_root
        or sealed.qualification_receipt_fingerprint
        != proposed.qualification_receipt_fingerprint
        or sealed.qualification_readiness != proposed.qualification_readiness
    ):
        reasons.add("QUALIFICATION_CHANGED")
    if (
        canonical_json_bytes(sealed.compiler_contract)
        != canonical_json_bytes(proposed.compiler_contract)
        or sealed.compiler_contract_fingerprint != proposed.compiler_contract_fingerprint
    ):
        reasons.add("COMPILER_CHANGED")
    if (
        sealed.evaluation_rubric_version != proposed.evaluation_rubric_version
        or sealed.evaluation_rubric_bytes != proposed.evaluation_rubric_bytes
        or sealed.evaluation_rubric_fingerprint != proposed.evaluation_rubric_fingerprint
    ):
        reasons.add("RUBRIC_CHANGED")
    if (
        sealed.importance_policy_version != proposed.importance_policy_version
        or sealed.importance_policy_bytes != proposed.importance_policy_bytes
        or sealed.importance_policy_fingerprint != proposed.importance_policy_fingerprint
    ):
        reasons.add("IMPORTANCE_POLICY_CHANGED")

    sealed_fingerprint = legal_input_fingerprint_v1(sealed)
    proposed_fingerprint = legal_input_fingerprint_v1(proposed)
    if (
        sealed.legal_input_fingerprint != sealed_fingerprint
        or proposed.legal_input_fingerprint != proposed_fingerprint
        or sealed_fingerprint != proposed_fingerprint
    ) and not reasons:
        reasons.add("LEGAL_INPUT_FINGERPRINT_CHANGED")
    return BaselineReuseDecisionV1(
        reusable=not reasons,
        reason_codes=cast(tuple[str, ...], tuple(sorted(reasons))),
    )
