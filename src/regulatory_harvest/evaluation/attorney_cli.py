"""Local-fixture command support for provider-neutral attorney evaluation.

The scripted judge exists solely for repository fixtures.  Applications must
provide an ``AttorneyEvaluationJudge`` to the public Python workflow API.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import tempfile
from datetime import date
from pathlib import Path
from typing import Literal, cast

from pydantic import ValidationError

from regulatory_harvest.models.enums import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from . import attorney_generation as generation
from .attorney_artifacts import (
    EvaluationIntegrityError,
    _open_run_storage,
    _RunStorage,
    load_verified_evaluation_run,
    verify_evaluation_run,
)
from .attorney_models import (
    AttorneyEvaluationCase,
    AttorneyEvaluationResult,
    CandidateReport,
    CandidateRole,
    EvaluationMode,
    EvaluationSource,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    QualificationCase,
    RequestedAuthority,
)
from .attorney_protocol import detect_evaluation_protocol
from .attorney_v2_artifacts import load_verified_v2_run, verify_v2_run
from .attorney_v2_models import (
    CompletedEvaluationV2,
    EvaluationResultV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    EvaluatorResponseV2,
)
from .attorney_v2_workflow import AttorneyEvaluatorV2
from .attorney_v21_artifacts import load_verified_v21_run, verify_v21_run
from .attorney_v21_models import (
    EvaluationManifestV21,
    EvaluationResultV21,
    EvaluationTerminalStatusV21,
    EvaluatorOperationV21,
    EvaluatorRequestV21,
    EvaluatorResponseV21,
)
from .attorney_v21_workflow import AttorneyEvaluatorV21, run_evaluation_v21
from .attorney_v22_artifacts import load_verified_v22_run
from .attorney_v22_drafts import (
    DraftReasonCodeV22,
    EvaluatorDraftPromptV22,
    EvaluatorProvenanceV22,
)
from .attorney_v22_models import (
    EvaluationCallRecordV22,
    EvaluationResultV22,
    EvaluatorOperationV22,
)
from .attorney_v22_workflow import (
    EvaluationDriverOutcomeV22,
    continue_evaluation_v22,
    resume_evaluation_v22,
    run_evaluation_v22,
)
from .attorney_workflow import (
    AttorneyEvaluationJudge,
    CompletedEvaluation,
    EvaluationSourceParityUnprovenError,
)

_EXIT_INPUT = 2
_EXIT_INCONCLUSIVE = 3
_EXIT_FAIL = 4
_EXIT_INTEGRITY = 5
_EXIT_ENGINE_PAUSED = 6
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_SCRIPTED_DRAFT_FIXTURE_BYTES = 16 * 1024 * 1024


def _json_line(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


class _FixtureReader:
    """Read only retained, no-follow fixture paths beneath one opened root."""

    def __init__(self, storage: _RunStorage) -> None:
        self._storage = storage

    @property
    def root_path(self) -> Path:
        return self._storage.root_path

    def read(
        self, relative: str, *, name: str, max_bytes: int | None = None
    ) -> bytes:
        path = Path(relative)
        if path.is_absolute() or not relative:
            raise ValueError(f"{name} has an unsafe fixture path")
        try:
            return self._storage.read_artifact(relative, max_bytes=max_bytes)
        except EvaluationIntegrityError as error:
            raise ValueError(f"{name} is unavailable") from error


def _canonical_object(data: bytes, *, name: str) -> dict[str, object]:
    try:
        parsed = json.loads(data.decode("utf-8"))
        canonical = canonical_json_bytes(parsed)
    except (
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError(f"{name} is not canonical JSON") from error
    if not isinstance(parsed, dict) or data not in {canonical, canonical + b"\n"}:
        raise ValueError(f"{name} is not canonical JSON")
    return cast(dict[str, object], parsed)


def _strict_string(value: object, *, name: str) -> str:
    """Require the literal JSON string type before model construction."""
    if type(value) is not str:
        raise ValueError(f"{name} must be a string")
    return value


def _read_text(relative: object, *, reader: _FixtureReader, name: str) -> str:
    if type(relative) is not str or not relative or Path(relative).is_absolute():
        raise ValueError(f"{name} has an unsafe fixture path")
    try:
        text = reader.read(relative, name=name).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{name} is not UTF-8") from error
    if not text.replace("\ufeff", "").strip():
        raise ValueError(f"{name} is blank")
    return text


def _fixture_relative_path(relative: object, *, name: str) -> str:
    if type(relative) is not str or not relative or Path(relative).is_absolute():
        raise ValueError(f"{name} has an unsafe fixture path")
    if "\\" in relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError(f"{name} has an unsafe fixture path")
    return relative


def _capsule_report(
    relative: object,
    *,
    reader: _FixtureReader,
) -> tuple[str, dict[str, object], dict[str, object], Path]:
    capsule_relative = _fixture_relative_path(relative, name="generation capsule")
    capsule_path = reader.root_path / capsule_relative
    try:
        provenance, report_bytes, request = generation.load_completed_generation_capsule_context(
            capsule_path
        )
    except generation.GenerationInputError as error:
        if "symlink or non-directory component" in str(error):
            raise generation.GenerationIntegrityError(str(error)) from error
        raise ValueError("generation capsule is incomplete") from error
    try:
        report = report_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("generation capsule report is not UTF-8") from error
    if not report.replace("\ufeff", "").strip():
        raise ValueError("generation capsule report is blank")
    return report, provenance, request, capsule_path


def _requested_authority(value: object, *, index: int) -> RequestedAuthority:
    name = f"requested authority {index}"
    required = {"authority_id", "title", "jurisdiction", "authority_type", "source_ids"}
    if type(value) is not dict or set(value) != required:
        raise ValueError(f"{name} has an unexpected shape")
    source_ids = value["source_ids"]
    if type(source_ids) is not list:
        raise ValueError(f"{name} source_ids must be an array")
    return RequestedAuthority(
        authority_id=_strict_string(value["authority_id"], name=f"{name} authority_id"),
        title=_strict_string(value["title"], name=f"{name} title"),
        jurisdiction=_strict_string(
            value["jurisdiction"], name=f"{name} jurisdiction"
        ),
        authority_type=_strict_string(
            value["authority_type"], name=f"{name} authority_type"
        ),
        source_ids=[
            _strict_string(source_id, name=f"{name} source_id")
            for source_id in source_ids
        ],
    )


def _case_from_bytes(
    data: bytes,
    *,
    reader: _FixtureReader,
) -> tuple[AttorneyEvaluationCase, dict[str, Path]]:
    value = _canonical_object(data, name="case fixture")
    required = {
        "case_id",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
        "candidates",
        "client_facts_path",
        "schema_version",
    }
    if set(value) != required:
        raise ValueError("case fixture has an unexpected shape")
    if value["schema_version"] != "1.1":
        raise ValueError("case fixture schema version is unsupported for initialization")
    case_question = _strict_string(value["question"], name="case question")
    sources_raw = value["sources"]
    candidates_raw = value["candidates"]
    if type(sources_raw) is not list or type(candidates_raw) is not list:
        raise ValueError("case fixture sources and candidates must be arrays")
    sources: list[EvaluationSource] = []
    for item in sources_raw:
        if type(item) is not dict or set(item) != {
            "source_id",
            "title",
            "path",
            "jurisdiction",
            "authority_type",
            "source_role",
            "source_quality",
            "completeness",
            "language",
        }:
            raise ValueError("case source has an unexpected shape")
        text = _read_text(item["path"], reader=reader, name="source fixture")
        sources.append(
            EvaluationSource(
                source_id=_strict_string(item["source_id"], name="source_id"),
                title=_strict_string(item["title"], name="source title"),
                normalized_text=text,
                content_hash=sha256_digest(text.encode("utf-8")),
                jurisdiction=_strict_string(
                    item["jurisdiction"], name="source jurisdiction"
                ),
                authority_type=_strict_string(
                    item["authority_type"], name="source authority_type"
                ),
                source_role=SourceRole(
                    _strict_string(item["source_role"], name="source role")
                ),
                source_quality=SourceQuality(
                    _strict_string(item["source_quality"], name="source quality")
                ),
                completeness=cast(
                    Literal[
                        "complete", "consolidated", "amending", "partial", "snippet", "unknown"
                    ],
                    _strict_string(item["completeness"], name="source completeness"),
                ),
                language=_strict_string(item["language"], name="source language"),
            )
        )
    client_facts = (
        None
        if value["client_facts_path"] is None
        else _read_text(
            value["client_facts_path"],
            reader=reader,
            name="client facts fixture",
        )
    )
    expected_source_hashes = {source.source_id: source.content_hash for source in sources}
    expected_client_facts_hash = (
        None if client_facts is None else sha256_digest(client_facts.encode("utf-8"))
    )
    candidates: list[CandidateReport] = []
    generation_capsule_paths: dict[str, Path] = {}
    for item in candidates_raw:
        if type(item) is not dict or set(item) != {
            "candidate_id",
            "external_report_path",
            "generation_capsule_path",
            "role",
        }:
            raise ValueError("case candidate has an unexpected shape")
        candidate_id = _strict_string(item["candidate_id"], name="candidate_id")
        capsule_path = item["generation_capsule_path"]
        external_path = item["external_report_path"]
        if (capsule_path is None) == (external_path is None):
            raise ValueError("case candidate must identify exactly one report source")
        if capsule_path is not None:
            text, provenance, request, verified_capsule_path = _capsule_report(
                capsule_path, reader=reader
            )
            record = cast(dict[str, object], provenance["generation_record"])
            if record["candidate_id"] != candidate_id:
                raise ValueError("generation capsule candidate_id does not match the case")
            if record["source_hashes"] != expected_source_hashes:
                raise EvaluationSourceParityUnprovenError(
                    "Generation capsule sources do not match the common case evidence."
                )
            if record["client_facts_hash"] != expected_client_facts_hash:
                raise EvaluationSourceParityUnprovenError(
                    "Generation capsule client facts do not match the common case evidence."
                )
            if request["question"] != case_question:
                raise EvaluationSourceParityUnprovenError(
                    "Generation capsule question does not match the evaluation question."
                )
            generation_capsule_paths[candidate_id] = verified_capsule_path
        else:
            text = _read_text(external_path, reader=reader, name="external report fixture")
            provenance = {"kind": "external"}
        candidates.append(
            CandidateReport(
                candidate_id=candidate_id,
                role=CandidateRole(_strict_string(item["role"], name="candidate role")),
                report_text=text,
                report_hash=sha256_digest(text.encode("utf-8")),
                validation_receipt=provenance,
            )
        )
    try:
        authorities_raw = value["requested_authorities"]
        if type(authorities_raw) is not list:
            raise ValueError("case fixture requested authorities must be an array")
        authorities = [
            _requested_authority(item, index=index)
            for index, item in enumerate(authorities_raw)
        ]
        return (
            AttorneyEvaluationCase(
                schema_version="1.1",
                case_id=_strict_string(value["case_id"], name="case_id"),
                mode=EvaluationMode(_strict_string(value["mode"], name="case mode")),
                question=case_question,
                jurisdiction=_strict_string(
                    value["jurisdiction"], name="case jurisdiction"
                ),
                as_of=date.fromisoformat(
                    _strict_string(value["as_of"], name="case as_of")
                ),
                requested_authorities=authorities,
                sources=sources,
                candidates=candidates,
                client_facts=client_facts,
            ),
            generation_capsule_paths,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("case fixture is invalid") from error


def _fixture_relative(path: Path, root: Path, *, name: str) -> str:
    try:
        value = Path(os.path.abspath(path))
        relative = value.relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError(f"{name} must be a local fixture below fixture root") from error
    if not relative.parts:
        raise ValueError(f"{name} must be a regular local fixture")
    return relative.as_posix()


def _fixture_inputs(
    case_path: Path,
    responses_path: Path,
) -> tuple[AttorneyEvaluationCase, dict[str, object], dict[str, Path]]:
    """Load case and scripted responses through one retained fixture root."""
    root = Path(os.path.abspath(case_path.parent))
    case_relative = _fixture_relative(case_path, root, name="case fixture")
    responses_relative = _fixture_relative(
        responses_path,
        root,
        name="scripted response fixture",
    )
    try:
        with _open_run_storage(root) as storage:
            reader = _FixtureReader(storage)
            case, capsule_paths = _case_from_bytes(
                reader.read(case_relative, name="case fixture"), reader=reader
            )
            responses = _canonical_object(
                reader.read(responses_relative, name="scripted response fixture"),
                name="scripted response fixture",
            )
            storage.assert_root_identity()
            return case, responses, capsule_paths
    except EvaluationIntegrityError as error:
        raise ValueError("fixture root is unavailable or changed") from error


def _scripted_drafts_from_fixture(path: Path) -> dict[str, object]:
    """Load one canonical draft fixture through its retained, no-follow parent."""
    root = Path(os.path.abspath(path.parent))
    relative = _fixture_relative(path, root, name="scripted draft fixture")
    try:
        with _open_run_storage(root) as storage:
            reader = _FixtureReader(storage)
            responses = _canonical_object(
                reader.read(
                    relative,
                    name="scripted draft fixture",
                    max_bytes=_MAX_SCRIPTED_DRAFT_FIXTURE_BYTES,
                ),
                name="scripted draft fixture",
            )
            storage.assert_root_identity()
            return responses
    except EvaluationIntegrityError as error:
        raise ValueError("scripted draft fixture root is unavailable or changed") from error


def _case_from_fixture(path: Path, *, root: Path) -> AttorneyEvaluationCase:
    """Test helper that applies the same retained-root fixture read boundary."""
    root = Path(os.path.abspath(root))
    case_relative = _fixture_relative(path, root, name="case fixture")
    try:
        with _open_run_storage(root) as storage:
            reader = _FixtureReader(storage)
            case, _ = _case_from_bytes(
                reader.read(case_relative, name="case fixture"), reader=reader
            )
            return case
    except EvaluationIntegrityError as error:
        raise ValueError("fixture root is unavailable or changed") from error


def _case_and_capsules_from_fixture(
    path: Path,
    *,
    root: Path,
) -> tuple[AttorneyEvaluationCase, dict[str, Path]]:
    """Load a case plus capsule roots for mutation-boundary re-verification."""
    root = Path(os.path.abspath(root))
    case_relative = _fixture_relative(path, root, name="case fixture")
    try:
        with _open_run_storage(root) as storage:
            reader = _FixtureReader(storage)
            return _case_from_bytes(
                reader.read(case_relative, name="case fixture"), reader=reader
            )
    except EvaluationIntegrityError as error:
        raise ValueError("fixture root is unavailable or changed") from error


def _qualification_case_from_bytes(
    data: bytes,
    *,
    reader: _FixtureReader,
) -> QualificationCase:
    """Load the strict candidate-free qualification fixture grammar."""
    value = _canonical_object(data, name="qualification case fixture")
    required = {
        "case_id",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
        "schema_version",
    }
    schema_version = value.get("schema_version")
    if schema_version == "1.1":
        required.update({"build_binding", "language_treatments"})
    elif schema_version != "1.0":
        raise ValueError("qualification case fixture schema version is unsupported")
    if set(value) != required:
        raise ValueError("qualification case fixture has an unexpected shape")
    sources_raw = value["sources"]
    authorities_raw = value["requested_authorities"]
    if type(sources_raw) is not list or type(authorities_raw) is not list:
        raise ValueError("qualification case fixture arrays are invalid")
    required_source_fields = {
        "source_id",
        "title",
        "path",
        "jurisdiction",
        "authority_type",
        "source_role",
        "source_quality",
        "completeness",
        "language",
    }
    optional_source_fields = {
        "qualification_role",
        "canonical_url",
        "publisher",
        "version",
        "effective_date",
        "supersession",
        "relationship_ids",
    }
    sources: list[EvaluationSource] = []
    for item in sources_raw:
        if (
            type(item) is not dict
            or not required_source_fields.issubset(item)
            or set(item) - required_source_fields - optional_source_fields
        ):
            raise ValueError("qualification case source has an unexpected shape")
        qualification_role = item.get("qualification_role")
        if qualification_role not in {None, "operative_text", "status_currentness"}:
            raise ValueError("qualification case source has an invalid qualification role")
        relationship_ids = item.get("relationship_ids", [])
        if type(relationship_ids) is not list:
            raise ValueError("qualification case source relationship_ids must be an array")
        text = _read_text(item["path"], reader=reader, name="source fixture")
        sources.append(
            EvaluationSource(
                source_id=_strict_string(item["source_id"], name="source_id"),
                title=_strict_string(item["title"], name="source title"),
                normalized_text=text,
                content_hash=sha256_digest(text.encode("utf-8")),
                canonical_url=(
                    None
                    if item.get("canonical_url") is None
                    else _strict_string(item["canonical_url"], name="source canonical_url")
                ),
                publisher=(
                    None
                    if item.get("publisher") is None
                    else _strict_string(item["publisher"], name="source publisher")
                ),
                jurisdiction=_strict_string(
                    item["jurisdiction"], name="source jurisdiction"
                ),
                authority_type=_strict_string(
                    item["authority_type"], name="source authority_type"
                ),
                source_role=SourceRole(
                    _strict_string(item["source_role"], name="source role")
                ),
                source_quality=SourceQuality(
                    _strict_string(item["source_quality"], name="source quality")
                ),
                completeness=cast(
                    Literal[
                        "complete", "consolidated", "amending", "partial", "snippet", "unknown"
                    ],
                    _strict_string(item["completeness"], name="source completeness"),
                ),
                language=_strict_string(item["language"], name="source language"),
                version=(
                    None
                    if item.get("version") is None
                    else _strict_string(item["version"], name="source version")
                ),
                effective_date=(
                    None
                    if item.get("effective_date") is None
                    else _strict_string(item["effective_date"], name="source effective_date")
                ),
                supersession=(
                    None
                    if item.get("supersession") is None
                    else _strict_string(item["supersession"], name="source supersession")
                ),
                relationship_ids=[
                    _strict_string(identifier, name="source relationship_id")
                    for identifier in relationship_ids
                ],
            )
        )
    try:
        payload: dict[str, object] = {
            "schema_version": schema_version,
            "case_id": _strict_string(value["case_id"], name="case_id"),
            "mode": EvaluationMode(_strict_string(value["mode"], name="case mode")),
            "question": _strict_string(value["question"], name="case question"),
            "jurisdiction": _strict_string(
                value["jurisdiction"], name="case jurisdiction"
            ),
            "as_of": date.fromisoformat(
                _strict_string(value["as_of"], name="case as_of")
            ),
            "requested_authorities": [
                _requested_authority(item, index=index)
                for index, item in enumerate(authorities_raw)
            ],
            "sources": sources,
        }
        if schema_version == "1.1":
            payload.update(
                {
                    "build_binding": value["build_binding"],
                    "language_treatments": value["language_treatments"],
                }
            )
        return QualificationCase.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("qualification case fixture is invalid") from error


def _qualification_case_from_fixture(path: Path, *, root: Path) -> QualificationCase:
    """Load a candidate-free case through one retained, no-follow fixture root."""
    root = Path(os.path.abspath(root))
    case_relative = _fixture_relative(path, root, name="qualification case fixture")
    try:
        with _open_run_storage(root) as storage:
            reader = _FixtureReader(storage)
            case = _qualification_case_from_bytes(
                reader.read(case_relative, name="qualification case fixture"),
                reader=reader,
            )
            storage.assert_root_identity()
            return case
    except EvaluationIntegrityError as error:
        raise ValueError("qualification fixture root is unavailable or changed") from error


class _ScriptedFixtureJudge(AttorneyEvaluationJudge):
    """Strict, deterministic, no-provider adapter for one local fixture file."""

    def __init__(self, responses: dict[str, object]) -> None:
        if (
            set(responses) != {"fixture_type", "responses"}
            or responses["fixture_type"] != "local-scripted"
        ):
            raise ValueError("scripted responses are not a local fixture")
        raw = responses["responses"]
        if not isinstance(raw, list):
            raise ValueError("scripted responses must be an array")
        self._responses: list[tuple[JudgeOperation, dict[str, object], dict[str, str]]] = []
        self._response_count = 0
        seen: set[bytes] = set()
        for item in raw:
            if not isinstance(item, dict) or set(item) != {"expect", "operation", "payload"}:
                raise ValueError("scripted response has an unexpected shape")
            operation = item["operation"]
            payload = item["payload"]
            expectation = item["expect"]
            if (
                not isinstance(operation, str)
                or not isinstance(payload, dict)
                or not isinstance(expectation, dict)
                or any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in expectation.items()
                )
            ):
                raise ValueError("scripted response is malformed")
            try:
                operation_value = JudgeOperation(operation)
            except ValueError as error:
                raise ValueError("scripted response has an unknown operation") from error
            if "request_fingerprint" not in expectation:
                raise ValueError("scripted response must bind an exact request fingerprint")
            signature = canonical_json_bytes(item)
            if signature in seen:
                raise ValueError("scripted response is duplicated")
            seen.add(signature)
            self._responses.append(
                (
                    operation_value,
                    cast(dict[str, object], payload),
                    cast(dict[str, str], expectation),
                )
            )

    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        self._response_count += 1
        if not self._responses:
            raise ValueError("scripted responses exhausted or operation mismatched")
        operation, stored_payload, expected = self._responses.pop(0)
        if operation is not request.operation:
            raise ValueError(
                "scripted response operation mismatched: "
                f"expected {operation.value}, got {request.operation.value}"
            )
        actual = {
            key: (
                request.request_fingerprint
                if key == "request_fingerprint"
                else str(request.safe_metadata.get(key, ""))
            )
            for key in expected
        }
        if actual != expected:
            raise ValueError("scripted response request mismatched")
        return JudgeResponse(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="local-scripted-fixture",
            model_name="no-provider",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id=f"fixture-response-{self._response_count}",
            payload=stored_payload,
        )

    def assert_exhausted(self) -> None:
        if self._responses:
            raise ValueError("scripted responses contain unused or duplicate entries")


class _ScriptedFixtureEvaluator(AttorneyEvaluatorV2):
    """Strict, deterministic protocol-2 fixture adapter with truthful provenance."""

    def __init__(self, responses: dict[str, object]) -> None:
        if (
            set(responses) != {"fixture_type", "responses"}
            or responses["fixture_type"] != "local-scripted"
        ):
            raise ValueError("scripted responses are not a local fixture")
        raw = responses["responses"]
        if not isinstance(raw, list):
            raise ValueError("scripted responses must be an array")
        self._responses: list[
            tuple[EvaluatorOperationV2, dict[str, object], dict[str, str]]
        ] = []
        self._response_count = 0
        seen: set[bytes] = set()
        for item in raw:
            if not isinstance(item, dict) or set(item) != {"expect", "operation", "payload"}:
                raise ValueError("scripted response has an unexpected shape")
            operation = item["operation"]
            payload = item["payload"]
            expectation = item["expect"]
            if (
                not isinstance(operation, str)
                or not isinstance(payload, dict)
                or not isinstance(expectation, dict)
                or any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in expectation.items()
                )
            ):
                raise ValueError("scripted response is malformed")
            try:
                operation_value = EvaluatorOperationV2(operation)
            except ValueError as error:
                raise ValueError("scripted response has an unknown operation") from error
            if "request_fingerprint" not in expectation:
                raise ValueError("scripted response must bind an exact request fingerprint")
            signature = canonical_json_bytes(item)
            if signature in seen:
                raise ValueError("scripted response is duplicated")
            seen.add(signature)
            self._responses.append(
                (
                    operation_value,
                    cast(dict[str, object], payload),
                    cast(dict[str, str], expectation),
                )
            )

    async def evaluate(self, request: EvaluatorRequestV2) -> EvaluatorResponseV2:
        self._response_count += 1
        if not self._responses:
            raise ValueError("scripted responses exhausted or operation mismatched")
        operation, stored_payload, expected = self._responses.pop(0)
        if operation is not request.operation:
            raise ValueError(
                "scripted response operation mismatched: "
                f"expected {operation.value}, got {request.operation.value}"
            )
        actual = {
            key: (
                request.request_fingerprint
                if key == "request_fingerprint"
                else str(request.safe_metadata.get(key, ""))
            )
            for key in expected
        }
        if actual != expected:
            raise ValueError("scripted response request mismatched")
        return EvaluatorResponseV2(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="local-scripted-fixture",
            model_name="no-provider",
            judge_isolation="scripted_fixture",
            payload=stored_payload,
        )

    def assert_exhausted(self) -> None:
        if self._responses:
            raise ValueError("scripted responses contain unused or duplicate entries")


class _ScriptedFixtureEvaluatorV21(AttorneyEvaluatorV21):
    """Strict, deterministic protocol-2.1 fixture adapter with truthful provenance."""

    def __init__(self, responses: dict[str, object]) -> None:
        if (
            set(responses) != {"fixture_type", "responses"}
            or responses["fixture_type"] != "local-scripted"
        ):
            raise ValueError("scripted responses are not a local fixture")
        raw = responses["responses"]
        if not isinstance(raw, list):
            raise ValueError("scripted responses must be an array")
        self._responses: list[
            tuple[EvaluatorOperationV21, dict[str, object], dict[str, str]]
        ] = []
        self._response_count = 0
        seen: set[bytes] = set()
        for item in raw:
            if not isinstance(item, dict) or set(item) != {"expect", "operation", "payload"}:
                raise ValueError("scripted response has an unexpected shape")
            operation = item["operation"]
            payload = item["payload"]
            expectation = item["expect"]
            if (
                not isinstance(operation, str)
                or not isinstance(payload, dict)
                or not isinstance(expectation, dict)
                or set(expectation) != {"request_fingerprint"}
                or any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in expectation.items()
                )
            ):
                raise ValueError("scripted response is malformed")
            try:
                operation_value = EvaluatorOperationV21(operation)
            except ValueError as error:
                raise ValueError("scripted response has an unknown operation") from error
            signature = canonical_json_bytes(item)
            if signature in seen:
                raise ValueError("scripted response is duplicated")
            seen.add(signature)
            self._responses.append(
                (
                    operation_value,
                    cast(dict[str, object], payload),
                    cast(dict[str, str], expectation),
                )
            )

    async def evaluate(self, request: EvaluatorRequestV21) -> EvaluatorResponseV21:
        self._response_count += 1
        if not self._responses:
            raise ValueError("scripted responses exhausted or operation mismatched")
        operation, stored_payload, expected = self._responses.pop(0)
        if operation is not request.operation:
            raise ValueError(
                "scripted response operation mismatched: "
                f"expected {operation.value}, got {request.operation.value}"
            )
        if expected["request_fingerprint"] != request.request_fingerprint:
            raise ValueError("scripted response request mismatched")
        return EvaluatorResponseV21(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="local-scripted-fixture",
            model_name="no-provider",
            judge_isolation="scripted_fixture",
            payload=stored_payload,
        )

    def assert_exhausted(self) -> None:
        if self._responses:
            raise ValueError("scripted responses contain unused or duplicate entries")


class _ScriptedDraftFixtureError(ValueError):
    """A local scripted-draft file does not match its declared prompt sequence."""


class _ScriptedDraftExhaustedError(_ScriptedDraftFixtureError):
    """A local scripted-draft file ends before the pending prompt sequence."""


class _ScriptedDraftProbeInputError(_ScriptedDraftFixtureError):
    """A disposable scripted-draft probe could not be constructed or read."""


class _ScriptedDraftProviderProbeError(Exception):
    """A provider failure observed while validating a disposable probe."""


class _ScriptedFixtureDraftEvaluatorV22:
    """Fixture-only semantic-draft adapter with controller-owned provenance."""

    provenance = EvaluatorProvenanceV22(
        provider_name="local-scripted-fixture",
        model_name="no-provider",
        judge_isolation="scripted_fixture",
    )

    def __init__(self, responses: dict[str, object]) -> None:
        if (
            set(responses) != {"fixture_type", "responses"}
            or responses["fixture_type"] != "local-scripted-drafts-v2.2"
        ):
            raise _ScriptedDraftFixtureError(
                "scripted drafts are not a Protocol 2.2 local fixture"
            )
        raw = responses["responses"]
        if not isinstance(raw, list):
            raise _ScriptedDraftFixtureError("scripted drafts must be an array")
        self._responses: list[
            tuple[
                EvaluatorOperationV22,
                object,
                str,
                Literal[1, 2],
                tuple[DraftReasonCodeV22, ...],
            ]
        ] = []
        seen: set[bytes] = set()
        for item in raw:
            if not isinstance(item, dict) or set(item) != {"draft", "expect", "operation"}:
                raise _ScriptedDraftFixtureError("scripted draft has an unexpected shape")
            operation = item["operation"]
            expectation = item["expect"]
            if type(operation) is not str or type(expectation) is not dict:
                raise _ScriptedDraftFixtureError("scripted draft is malformed")
            expected = cast(dict[str, object], expectation)
            if set(expected) != {
                "attempt",
                "clarification_codes",
                "request_fingerprint",
            }:
                raise _ScriptedDraftFixtureError(
                    "scripted draft expectation has an unexpected shape"
                )
            attempt = expected["attempt"]
            fingerprint = expected["request_fingerprint"]
            clarification_codes = expected["clarification_codes"]
            if (
                type(attempt) is not int
                or attempt not in {1, 2}
                or type(fingerprint) is not str
                or _HASH_RE.fullmatch(fingerprint) is None
                or type(clarification_codes) is not list
                or any(type(code) is not str for code in clarification_codes)
            ):
                raise _ScriptedDraftFixtureError("scripted draft expectation is malformed")
            try:
                operation_value = EvaluatorOperationV22(operation)
                codes = tuple(DraftReasonCodeV22(code) for code in clarification_codes)
            except ValueError as error:
                raise _ScriptedDraftFixtureError(
                    "scripted draft expectation is unsupported"
                ) from error
            signature = canonical_json_bytes(item)
            if signature in seen:
                raise _ScriptedDraftFixtureError("scripted draft is duplicated")
            seen.add(signature)
            self._responses.append(
                (
                    operation_value,
                    item["draft"],
                    fingerprint,
                    cast(Literal[1, 2], attempt),
                    codes,
                )
            )

    async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
        if not self._responses:
            raise _ScriptedDraftExhaustedError("scripted drafts exhausted")
        operation, draft, fingerprint, attempt, clarification_codes = self._responses.pop(0)
        if (
            operation is not prompt.request.operation
            or fingerprint != prompt.request.request_fingerprint
            or attempt != prompt.attempt
            or clarification_codes != prompt.clarification_codes
        ):
            raise _ScriptedDraftFixtureError("scripted draft prompt mismatched")
        return draft

    def assert_exhausted(self) -> None:
        if self._responses:
            raise _ScriptedDraftFixtureError("scripted drafts contain unused entries")


class _ScriptedDraftProbeEvaluatorV22:
    """Keep provider failures distinct from disposable-probe storage failures."""

    def __init__(self, evaluator: _ScriptedFixtureDraftEvaluatorV22) -> None:
        self._evaluator = evaluator
        self.provenance = evaluator.provenance

    async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
        try:
            return await self._evaluator.evaluate_draft(prompt)
        except _ScriptedDraftFixtureError:
            raise
        except Exception as error:
            raise _ScriptedDraftProviderProbeError from error


def _caused_by_oserror(error: BaseException) -> bool:
    cause: BaseException | None = error
    seen: set[int] = set()
    while cause is not None and id(cause) not in seen:
        if isinstance(cause, OSError):
            return True
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
    return False


def _probe_new_scripted_v22_run(
    case: AttorneyEvaluationCase,
    responses: dict[str, object],
    capsule_paths: dict[str, Path],
) -> None:
    """Validate a deterministic fixture completely before touching its real run."""
    evaluator = _ScriptedFixtureDraftEvaluatorV22(responses)
    with tempfile.TemporaryDirectory(prefix="regulatory-harvest-v22-probe-") as temporary:
        probe = Path(os.path.realpath(temporary)) / "run"
        try:
            asyncio.run(
                run_evaluation_v22(
                    case,
                    evaluator,
                    probe,
                    seed_hex="0" * 64,
                    generation_capsule_paths=capsule_paths,
                )
            )
        except (EvaluationIntegrityError, _ScriptedDraftFixtureError):
            raise
        except Exception:
            # Only fixture-sequence defects are input errors. Provider/runtime
            # failures must still be exercised against, and pause, the real run.
            return
        evaluator.assert_exhausted()


def _probe_resumed_scripted_v22_run(
    run_path: Path,
    responses: dict[str, object],
) -> None:
    """Validate a resume fixture against a disposable exact run copy."""
    # Stored-run failures are integrity failures. Complete this verification
    # before entering the disposable-probe I/O boundary below.
    load_verified_v22_run(run_path)
    evaluator = _ScriptedFixtureDraftEvaluatorV22(responses)
    probe_evaluator = _ScriptedDraftProbeEvaluatorV22(evaluator)
    try:
        with tempfile.TemporaryDirectory(
            prefix="regulatory-harvest-v22-probe-"
        ) as temporary:
            probe = Path(os.path.realpath(temporary)) / "run"
            shutil.copytree(run_path, probe, symlinks=True)
            asyncio.run(continue_evaluation_v22(probe, probe_evaluator))
            evaluator.assert_exhausted()
    except _ScriptedDraftProviderProbeError:
        # Exercise the provider failure on the retained run so the ordinary
        # verified pause/recovery boundary remains authoritative.
        return
    except _ScriptedDraftFixtureError:
        raise
    except EvaluationIntegrityError as error:
        if not _caused_by_oserror(error):
            raise
        raise _ScriptedDraftProbeInputError(
            "scripted draft probe could not be read"
        ) from error
    except OSError as error:
        raise _ScriptedDraftProbeInputError(
            "scripted draft probe could not be constructed"
        ) from error
    except Exception:
        # Preserve the real compiler/runtime failure route as a verified pause.
        return


def _existing_evaluation_protocol(run_path: Path) -> str | None:
    """Return an existing nonempty run protocol through secure storage."""
    if not run_path.exists():
        return None
    with _open_run_storage(run_path) as storage:
        files = storage.scan_files()
        storage.assert_root_identity()
    if not files:
        return None
    return detect_evaluation_protocol(run_path)


def _verified_protocol_for_v22_initialization(run_path: Path) -> str | None:
    """Detect and verify a retained root before explicit Protocol 2.2 init."""
    protocol = _existing_evaluation_protocol(run_path)
    if protocol is None:
        return None
    if protocol == "1.3":
        valid = verify_evaluation_run(run_path).valid
    elif protocol == "2.0":
        valid = verify_v2_run(run_path).valid
    elif protocol == "2.1":
        valid = verify_v21_run(run_path).valid
    else:
        return protocol
    if not valid:
        raise EvaluationIntegrityError("EVALUATION_RETAINED_RUN_INVALID")
    return protocol


def _run_payload(completed: CompletedEvaluation) -> dict[str, object]:
    terminal_status = completed.manifest.terminal_status
    if terminal_status is None:
        raise EvaluationIntegrityError("completed evaluation has no terminal status")
    reports = _report_payload(completed.result)
    all_issue_codes = _result_issue_codes(completed.result, reports)
    return {
        "terminal_state": terminal_status.value,
        "reports": reports,
        "comparative_disposition": None
        if completed.result.comparison is None
        else completed.result.comparison.disposition.value,
        "run_path": str(completed.run_dir),
        "manifest_root": completed.manifest.manifest_fingerprint,
        "all_issue_codes": all_issue_codes,
        "judge_mode": "local-scripted-fixture",
    }


def _report_payload(result: AttorneyEvaluationResult) -> list[dict[str, object]]:
    return [
        {
            "absolute_disposition": item.absolute_disposition.value,
            "issue_codes": item.issue_codes,
            "blocking_codes": item.blocking_codes,
            "all_issue_codes": sorted(set(item.issue_codes) | set(item.blocking_codes)),
        }
        for item in result.reports
    ]


def _result_issue_codes(
    result: AttorneyEvaluationResult,
    reports: list[dict[str, object]],
) -> list[str]:
    return (
        sorted(set(result.readiness.issue_codes))
        if not reports
        else sorted(
            {
                code
                for report in result.reports
                for code in [*report.issue_codes, *report.blocking_codes]
            }
        )
    )


def _v2_report_payload(result: EvaluationResultV2) -> list[dict[str, object]]:
    return [
        {
            "absolute_disposition": item.absolute_disposition.value,
            "reason_codes": list(item.reason_codes),
        }
        for item in result.reports
    ]


def _v2_run_payload(completed: CompletedEvaluationV2, run_path: Path) -> dict[str, object]:
    reports = _v2_report_payload(completed.result)
    terminal_status = completed.state.terminal_status
    if terminal_status is None:
        raise EvaluationIntegrityError("completed evaluation has no terminal status")
    return {
        "terminal_state": terminal_status.value,
        "reports": reports,
        "comparative_disposition": None
        if completed.result.comparison is None
        else completed.result.comparison.disposition.value,
        "run_path": str(run_path),
        "manifest_root": completed.manifest.manifest_fingerprint,
        "all_issue_codes": sorted(
            {code for report in completed.result.reports for code in report.reason_codes}
        ),
        "judge_mode": "local-scripted-fixture",
    }


def _v21_run_payload(result: EvaluationResultV21, run_path: Path) -> dict[str, object]:
    return {
        "terminal_state": result.terminal_status.value,
        "reports": [
            {
                "absolute_disposition": report.reconciliation.absolute_disposition.value,
                "reason_codes": list(report.reconciliation.reason_codes),
            }
            for report in result.reports
        ],
        "comparative_disposition": None
        if result.comparison is None
        else result.comparison.disposition.value,
        "run_path": str(run_path),
        "all_issue_codes": sorted(
            {code for report in result.reports for code in report.reconciliation.reason_codes}
        ),
        "judge_mode": "local-scripted-fixture",
    }


def _v21_mechanical_terminal_payload(
    manifest: EvaluationManifestV21, run_path: Path, *, judge_mode: str
) -> dict[str, object]:
    """Render the one verified terminal that intentionally has no result artifact."""
    if manifest.terminal_status is not EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL:
        raise EvaluationIntegrityError("verified evaluation has no result")
    return {
        "terminal_state": manifest.terminal_status.value,
        "reports": [],
        "comparative_disposition": None,
        "run_path": str(run_path),
        "manifest_root": manifest.manifest_fingerprint,
        "all_issue_codes": [],
        "judge_mode": judge_mode,
    }


def _v22_public_call_id(call: EvaluationCallRecordV22) -> str:
    if call.operation in {
        EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
    }:
        if call.fragment_ordinal is None:
            raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
        return f"{call.operation.value.replace('_', '-')}-{call.fragment_ordinal:04d}"
    return call.call_id


def _v22_nonterminal_payload(run_path: Path) -> dict[str, object]:
    manifest, result = load_verified_v22_run(run_path)
    if manifest.terminal_status is not None or result is not None:
        raise EvaluationIntegrityError("EVALUATOR_V22_NONTERMINAL_REQUIRED")
    pending = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    return {
        "compiler_contract_fingerprint": manifest.compiler_contract_fingerprint,
        "manifest_root": manifest.manifest_fingerprint,
        "pending_call": _v22_public_call_id(pending[0]),
        "phase": manifest.phase.value,
    }


def _v22_result_payload(
    result: EvaluationResultV22,
    run_path: Path,
    *,
    judge_mode: str,
) -> dict[str, object]:
    manifest, verified_result = load_verified_v22_run(run_path)
    if verified_result is None or verified_result != result:
        raise EvaluationIntegrityError("EVALUATOR_V22_RESULT_REQUIRED")
    reports = [
        {
            "absolute_disposition": report.sensitivity.absolute_disposition.value,
            "reason_codes": list(report.sensitivity.reason_codes),
        }
        for report in result.reports
    ]
    return {
        "all_issue_codes": sorted(
            {code for report in result.reports for code in report.sensitivity.reason_codes}
        ),
        "comparative_disposition": (
            None if result.comparison is None else result.comparison.disposition.value
        ),
        "judge_mode": judge_mode,
        "manifest_root": manifest.manifest_fingerprint,
        "reports": reports,
        "terminal_state": result.terminal_status.value,
    }


def _v22_outcome_payload(
    outcome: EvaluationDriverOutcomeV22,
    run_path: Path,
    *,
    judge_mode: str,
) -> dict[str, object]:
    if outcome.engine_paused:
        payload = _v22_nonterminal_payload(run_path)
        return {
            "error": "evaluation_engine_paused",
            "ok": False,
            "pending_call": payload["pending_call"],
        }
    if outcome.result is None:
        return _v22_nonterminal_payload(run_path)
    return _v22_result_payload(outcome.result, run_path, judge_mode=judge_mode)


def run_attorney_command(args: argparse.Namespace) -> int:
    if args.attorney_command == "verify":
        try:
            protocol = detect_evaluation_protocol(args.output)
            if protocol == "2.2":
                _v22_manifest, v22_result = load_verified_v22_run(args.output)
                v22_verification_payload = (
                    _v22_nonterminal_payload(args.output)
                    if v22_result is None
                    else _v22_result_payload(
                        v22_result,
                        args.output,
                        judge_mode="verification-only",
                    )
                )
                if args.json_output:
                    _json_line(v22_verification_payload)
                if v22_result is None:
                    return 0
                if v22_result.terminal_status.value == "INCONCLUSIVE":
                    return _EXIT_INCONCLUSIVE
                return (
                    _EXIT_FAIL
                    if any(
                        report.sensitivity.absolute_disposition.value == "FAIL"
                        for report in v22_result.reports
                    )
                    else 0
                )
            if protocol == "2.0":
                v2_manifest, v2_result = load_verified_v2_run(args.output)
                if v2_result is None:
                    raise EvaluationIntegrityError("verified evaluation has no result")
                terminal_status = v2_manifest.terminal_status
                if terminal_status is None:
                    raise EvaluationIntegrityError("verified evaluation has no terminal status")
                v2_verification_payload: dict[str, object] = {
                    "terminal_state": terminal_status.value,
                    "run_path": str(args.output),
                    "manifest_root": v2_manifest.manifest_fingerprint,
                    "reports": _v2_report_payload(v2_result),
                    "comparative_disposition": None
                    if v2_result.comparison is None
                    else v2_result.comparison.disposition.value,
                    "all_issue_codes": sorted(
                        {code for report in v2_result.reports for code in report.reason_codes}
                    ),
                    "judge_mode": "verification-only",
                }
                if args.json_output:
                    _json_line(v2_verification_payload)
                return 0
            if protocol == "2.1":
                v21_manifest, v21_result = load_verified_v21_run(args.output)
                if v21_manifest.terminal_status is None:
                    raise EvaluationIntegrityError("verified evaluation has no result")
                v21_verification_payload = (
                    _v21_mechanical_terminal_payload(
                        v21_manifest, args.output, judge_mode="verification-only"
                    )
                    if v21_result is None
                    else _v21_run_payload(v21_result, args.output)
                )
                v21_verification_payload[
                    "manifest_root"
                ] = v21_manifest.manifest_fingerprint
                v21_verification_payload["judge_mode"] = "verification-only"
                if args.json_output:
                    _json_line(v21_verification_payload)
                return (
                    _EXIT_INCONCLUSIVE
                    if v21_result is None
                    else 0
                )
            if protocol != "1.3":
                raise EvaluationIntegrityError("unsupported evaluation protocol")
            legacy_manifest, legacy_result = load_verified_evaluation_run(args.output)
            legacy_terminal_status = legacy_manifest.terminal_status
            if legacy_terminal_status is None:
                raise EvaluationIntegrityError("verified evaluation has no terminal status")
            legacy_verification_payload: dict[str, object] = {
                "terminal_state": legacy_terminal_status.value,
                "run_path": str(args.output),
                "manifest_root": legacy_manifest.manifest_fingerprint,
                "reports": _report_payload(legacy_result),
                "comparative_disposition": None
                if legacy_result.comparison is None
                else legacy_result.comparison.disposition.value,
                "all_issue_codes": _result_issue_codes(
                    legacy_result, _report_payload(legacy_result)
                ),
                "judge_mode": "verification-only",
            }
            if args.json_output:
                _json_line(legacy_verification_payload)
            return 0
        except (EvaluationIntegrityError, OSError, ValidationError, ValueError, TypeError):
            if args.json_output:
                _json_line({"error": "evaluation_integrity_invalid", "ok": False})
            return _EXIT_INTEGRITY
    if args.attorney_command == "resume":
        try:
            protocol = detect_evaluation_protocol(args.output)
            if protocol != "2.2":
                if args.json_output:
                    _json_line({"error": "evaluation_retained_read_only", "ok": False})
                return _EXIT_INPUT
            responses = _scripted_drafts_from_fixture(args.scripted_responses)
            _probe_resumed_scripted_v22_run(args.output, responses)
            evaluator = _ScriptedFixtureDraftEvaluatorV22(responses)
            try:
                outcome = asyncio.run(continue_evaluation_v22(args.output, evaluator))
            except (EvaluationIntegrityError, _ScriptedDraftFixtureError):
                raise
            except Exception:
                resume_evaluation_v22(args.output)
                if args.json_output:
                    _json_line(
                        {
                            "error": "evaluation_engine_paused",
                            "ok": False,
                            "pending_call": _v22_nonterminal_payload(args.output)[
                                "pending_call"
                            ],
                        }
                    )
                return _EXIT_ENGINE_PAUSED
            evaluator.assert_exhausted()
            if args.json_output:
                _json_line(
                    _v22_outcome_payload(
                        outcome,
                        args.output,
                        judge_mode="local-scripted-fixture",
                    )
                )
            return outcome.exit_code
        except (EvaluationIntegrityError, OSError):
            if args.json_output:
                _json_line({"error": "evaluation_integrity_invalid", "ok": False})
            return _EXIT_INTEGRITY
        except (ValidationError, ValueError, TypeError):
            if args.json_output:
                _json_line({"error": "attorney_input_invalid", "ok": False})
            return _EXIT_INPUT
    if args.protocol == "2.2":
        try:
            existing_protocol = _verified_protocol_for_v22_initialization(args.output)
        except (EvaluationIntegrityError, OSError, TypeError, ValueError):
            if args.json_output:
                _json_line({"error": "evaluation_integrity_invalid", "ok": False})
            return _EXIT_INTEGRITY
        if existing_protocol in {"1.3", "2.0", "2.1"}:
            if args.json_output:
                _json_line({"error": "evaluation_retained_read_only", "ok": False})
            return _EXIT_INPUT
    if args.scripted_responses is None:
        if args.json_output:
            _json_line({"error": "scripted_fixture_required", "ok": False})
        return _EXIT_INPUT
    try:
        case, responses, capsule_paths = _fixture_inputs(args.case, args.scripted_responses)
        if args.protocol == "2.2":
            _probe_new_scripted_v22_run(case, responses, capsule_paths)
            evaluator_v22 = _ScriptedFixtureDraftEvaluatorV22(responses)
            try:
                outcome_v22 = asyncio.run(
                    run_evaluation_v22(
                        case,
                        evaluator_v22,
                        args.output,
                        seed_hex="0" * 64,
                        generation_capsule_paths=capsule_paths,
                    )
                )
            except (EvaluationIntegrityError, _ScriptedDraftFixtureError):
                raise
            except Exception:
                resume_evaluation_v22(args.output)
                if args.json_output:
                    _json_line(
                        {
                            "error": "evaluation_engine_paused",
                            "ok": False,
                            "pending_call": _v22_nonterminal_payload(args.output)[
                                "pending_call"
                            ],
                        }
                    )
                return _EXIT_ENGINE_PAUSED
            evaluator_v22.assert_exhausted()
            if args.json_output:
                _json_line(
                    _v22_outcome_payload(
                        outcome_v22,
                        args.output,
                        judge_mode="local-scripted-fixture",
                    )
                )
            return outcome_v22.exit_code
        evaluator_v21 = _ScriptedFixtureEvaluatorV21(responses)
        try:
            completed = asyncio.run(
                run_evaluation_v21(
                    case,
                    evaluator_v21,
                    args.output,
                    seed_hex="0" * 64,
                    generation_capsule_paths=capsule_paths,
                )
            )
        except EvaluationIntegrityError:
            v21_manifest, v21_result = load_verified_v21_run(args.output)
            if v21_result is not None:
                raise
            evaluator_v21.assert_exhausted()
            payload = _v21_mechanical_terminal_payload(
                v21_manifest, args.output, judge_mode="local-scripted-fixture"
            )
            if args.json_output:
                _json_line(payload)
            return _EXIT_INCONCLUSIVE
        evaluator_v21.assert_exhausted()
        payload = _v21_run_payload(completed, args.output)
        if args.json_output:
            _json_line(payload)
        if any(
            report.reconciliation.absolute_disposition.value == "INCONCLUSIVE"
            for report in completed.reports
        ):
            return _EXIT_INCONCLUSIVE
        return (
            _EXIT_FAIL
            if any(
                report.reconciliation.absolute_disposition.value == "FAIL"
                for report in completed.reports
            )
            else 0
        )
    except (EvaluationIntegrityError, OSError):
        if args.json_output:
            _json_line({"error": "evaluation_integrity_invalid", "ok": False})
        return _EXIT_INTEGRITY
    except (ValidationError, ValueError, TypeError):
        if args.json_output:
            _json_line({"error": "attorney_input_invalid", "ok": False})
        return _EXIT_INPUT
