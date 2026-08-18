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
from .attorney_workflow import (
    AttorneyEvaluationJudge,
    CompletedEvaluation,
    EvaluationSourceParityUnprovenError,
    run_evaluation,
)

_EXIT_INPUT = 2
_EXIT_INCONCLUSIVE = 3
_EXIT_FAIL = 4
_EXIT_INTEGRITY = 5
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _json_line(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


class _FixtureReader:
    """Read only retained, no-follow fixture paths beneath one opened root."""

    def __init__(self, storage: _RunStorage) -> None:
        self._storage = storage

    @property
    def root_path(self) -> Path:
        return self._storage.root_path

    def read(self, relative: str, *, name: str) -> bytes:
        path = Path(relative)
        if path.is_absolute() or not relative:
            raise ValueError(f"{name} has an unsafe fixture path")
        try:
            return self._storage.read_artifact(relative)
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


def run_attorney_command(args: argparse.Namespace) -> int:
    if args.attorney_command == "verify":
        try:
            manifest, result = load_verified_evaluation_run(args.output)
            terminal_status = manifest.terminal_status
            if terminal_status is None:
                raise EvaluationIntegrityError("verified evaluation has no terminal status")
            verification_payload: dict[str, object] = {
                "terminal_state": terminal_status.value,
                "run_path": str(args.output),
                "manifest_root": manifest.manifest_fingerprint,
                "reports": _report_payload(result),
                "comparative_disposition": None
                if result.comparison is None
                else result.comparison.disposition.value,
                "all_issue_codes": _result_issue_codes(result, _report_payload(result)),
                "judge_mode": "verification-only",
            }
            if args.json_output:
                _json_line(verification_payload)
            return 0
        except (EvaluationIntegrityError, OSError, ValidationError, ValueError, TypeError):
            if args.json_output:
                _json_line({"error": "evaluation_integrity_invalid", "ok": False})
            return _EXIT_INTEGRITY
    if args.scripted_responses is None:
        if args.json_output:
            _json_line({"error": "scripted_fixture_required", "ok": False})
        return _EXIT_INPUT
    try:
        case, responses, capsule_paths = _fixture_inputs(args.case, args.scripted_responses)
        judge = _ScriptedFixtureJudge(responses)
        completed = asyncio.run(
            run_evaluation(
                case,
                judge,
                args.output,
                seed_hex="0" * 64,
                generation_capsule_paths=capsule_paths,
            )
        )
        judge.assert_exhausted()
        payload: dict[str, object] = _run_payload(completed)
        if args.json_output:
            _json_line(payload)
        if completed.result.readiness.status.value != "ADMITTED" or any(
            report.absolute_disposition.value == "INCONCLUSIVE"
            for report in completed.result.reports
        ):
            return _EXIT_INCONCLUSIVE
        return (
            _EXIT_FAIL
            if any(
                report.absolute_disposition.value == "FAIL" for report in completed.result.reports
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
