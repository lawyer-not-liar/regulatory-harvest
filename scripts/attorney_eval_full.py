#!/usr/bin/env python3
"""Dependency-minimal entry point for the full attorney evaluation runtime.

This module intentionally imports only the evaluation substrate.  The combined
``harvest_skill.py`` runner dispatches here before importing the research and
briefing stack, so an evaluation install is not coupled to unrelated model
surfaces.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from typing import Literal, Never, cast

from pydantic import ValidationError

from regulatory_harvest.evaluation import attorney_generation as generation
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
    load_verified_evaluation_run,
    read_evaluation_artifact,
    verify_evaluation_run,
)
from regulatory_harvest.evaluation.attorney_baseline_artifacts import verify_baseline_run
from regulatory_harvest.evaluation.attorney_baseline_input import BaselineInputError
from regulatory_harvest.evaluation.attorney_baseline_models import BASELINE_PROTOCOL_V1
from regulatory_harvest.evaluation.attorney_baseline_workflow import (
    BASELINE_EXTERNAL_RESPONSE_INVALID,
    baseline_status_payload_v1,
    guarded_submit_baseline_response_v1,
    initialize_baseline_v1,
    next_baseline_request_v1,
)
from regulatory_harvest.evaluation.attorney_cli import (
    _case_and_capsules_from_fixture,
    _probe_resumed_scripted_v22_run,
    _qualification_case_from_fixture,
    _scripted_drafts_from_fixture,
    _ScriptedDraftFixtureError,
    _ScriptedFixtureDraftEvaluatorV22,
    _v22_nonterminal_payload,
    _v22_outcome_payload,
    _v22_result_payload,
    _verified_protocol_for_v22_initialization,
)
from regulatory_harvest.evaluation.attorney_models import (
    EvaluationPreflightIssue,
    EvaluationPreflightResult,
    EvaluationRunState,
    GuardedSubmissionResult,
    JudgeRequest,
    JudgeResponse,
    QualificationSubmissionResult,
)
from regulatory_harvest.evaluation.attorney_protocol import detect_evaluation_protocol
from regulatory_harvest.evaluation.attorney_qualification import (
    guarded_submit_case_qualification,
    initialize_case_qualification,
    next_qualification_request,
    resume_case_qualification,
    verify_case_qualification,
)
from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    VerifiedReadinessContextV1,
    load_verified_readiness_context_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import ReadinessInputError
from regulatory_harvest.evaluation.attorney_readiness_models import (
    READINESS_PROTOCOL_V1,
    DeliveryReadinessResultV1,
    ReadinessEvaluatorRequestV1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    READINESS_EXTERNAL_RESPONSE_INVALID,
    GuardedReadinessSubmissionResultV1,
    guarded_submit_readiness_response_v1,
    initialize_readiness_v1,
    next_readiness_request_v1,
    readiness_exit_code_v1,
)
from regulatory_harvest.evaluation.attorney_v2_artifacts import (
    V2ResponsePreflight,
    load_verified_v2_run,
    verify_v2_run,
)
from regulatory_harvest.evaluation.attorney_v2_models import EvaluationRunStateV2
from regulatory_harvest.evaluation.attorney_v2_workflow import (
    GuardedSubmissionResultV2,
    guarded_submit_evaluator_response_v2,
    next_evaluator_request_v2,
    preflight_evaluator_response_v2,
    resume_evaluation_v2,
    stop_evaluation_v2_inconclusive,
    submit_evaluator_response_v2,
)
from regulatory_harvest.evaluation.attorney_v21_artifacts import (
    V21ResponsePreflight,
    load_verified_v21_run,
    verify_v21_run,
)
from regulatory_harvest.evaluation.attorney_v21_models import EvaluationRunStateV21
from regulatory_harvest.evaluation.attorney_v21_workflow import (
    GuardedSubmissionResultV21,
    guarded_submit_evaluator_response_v21,
    initialize_evaluation_v21,
    next_evaluator_request_v21,
    preflight_evaluator_response_v21,
    resume_evaluation_v21,
    stop_evaluation_v21_inconclusive,
    submit_evaluator_response_v21,
)
from regulatory_harvest.evaluation.attorney_v22_artifacts import (
    V22ResponsePreflight,
    load_verified_v22_run,
    verify_v22_run,
)
from regulatory_harvest.evaluation.attorney_v22_models import EvaluationRunStateV22
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    GuardedSubmissionResultV22,
    continue_evaluation_v22,
    guarded_submit_evaluator_response_v22,
    initialize_evaluation_v22,
    next_evaluator_request_v22,
    preflight_evaluator_response_v22,
    resume_evaluation_v22,
    submit_evaluator_response_v22,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    EvaluationSourceParityUnprovenError,
    guarded_submit_judge_response,
    next_judge_request,
    preflight_judge_response,
    resume_evaluation,
    submit_judge_response,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

EVAL_EXIT_SUCCESS = 0
EVAL_EXIT_INPUT = 2
EVAL_EXIT_INCONCLUSIVE = 3
EVAL_EXIT_FAIL = 4
EVAL_EXIT_INTEGRITY = 5
EVAL_EXIT_ENGINE_PAUSED = 6
_EVAL_RESPONSE_MAX_BYTES = 1024 * 1024
_EVAL_RESPONSE_MAX_DEPTH = 64
EVALUATION_INTEGRITY_INVALID = "EVALUATION_INTEGRITY_INVALID"
EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED = "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"
EVALUATION_STORAGE_PLATFORM_UNSUPPORTED = "EVALUATION_STORAGE_PLATFORM_UNSUPPORTED"
_CORE_SCHEMA_FAILURES = frozenset(
    {
        "resolved grade schema version is unsupported",
        "score inputs schema version is unsupported",
        "report disputes schema version is unsupported",
    }
)
_CORE_STORAGE_FAILURE_PREFIX = "secure evaluation storage is unavailable on platform: "
_CORE_STORAGE_FAILURES = frozenset({"POSIX storage is unavailable on this platform"})


class EvaluationCliInputError(ValueError):
    """A stable, user-facing evaluation command input error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise EvaluationCliInputError("INVALID_ARGUMENTS", message)


def _write_error(code: str, message: str) -> None:
    sys.stderr.write(json.dumps({"code": code, "message": message}, sort_keys=True) + "\n")


def _validation_message(error: ValidationError) -> str:
    messages: list[str] = []
    for item in error.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        messages.append(f"{location}: {item['msg']}")
    return "; ".join(messages)


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(prog="harvest-skill")
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=_JsonArgumentParser
    )
    baseline_init_parser = subparsers.add_parser("eval-baseline-init")
    baseline_init_parser.add_argument("--input", required=True)
    baseline_init_parser.add_argument("--run", required=True)
    baseline_init_parser.add_argument("--nonce-hex", required=True)
    baseline_init_parser.add_argument("--prior-baseline", action="append")
    baseline_init_parser.add_argument("--correction")
    baseline_next_parser = subparsers.add_parser("eval-baseline-next")
    baseline_next_parser.add_argument("--run", required=True)
    baseline_submit_parser = subparsers.add_parser("eval-baseline-submit-safe")
    baseline_submit_parser.add_argument("--run", required=True)
    baseline_submit_parser.add_argument("--response", required=True)
    baseline_submit_parser.add_argument("--provider-name", required=True)
    baseline_submit_parser.add_argument("--model-name", required=True)
    baseline_submit_parser.add_argument(
        "--judge-isolation",
        choices=("fresh_context", "scripted_fixture"),
        required=True,
    )
    baseline_status_parser = subparsers.add_parser("eval-baseline-status")
    baseline_status_parser.add_argument("--run", required=True)
    baseline_verify_parser = subparsers.add_parser("eval-baseline-verify")
    baseline_verify_parser.add_argument("--run", required=True)
    readiness_init_parser = subparsers.add_parser("eval-readiness-init")
    readiness_init_parser.add_argument("--baseline-run", required=True)
    readiness_init_parser.add_argument("--qualification-run", required=True)
    readiness_init_parser.add_argument("--generation-run", required=True)
    readiness_init_parser.add_argument("--validation-receipt", required=True)
    readiness_init_parser.add_argument("--run", required=True)
    readiness_init_parser.add_argument("--historical-v22-run")
    readiness_init_parser.add_argument("--historical-report-label", choices=("A", "B"))
    readiness_next_parser = subparsers.add_parser("eval-readiness-next")
    readiness_next_parser.add_argument("--run", required=True)
    readiness_submit_parser = subparsers.add_parser("eval-readiness-submit-safe")
    readiness_submit_parser.add_argument("--run", required=True)
    readiness_submit_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(readiness_submit_parser)
    readiness_status_parser = subparsers.add_parser("eval-readiness-status")
    readiness_status_parser.add_argument("--run", required=True)
    readiness_verify_parser = subparsers.add_parser("eval-readiness-verify")
    readiness_verify_parser.add_argument("--run", required=True)
    eval_init_parser = subparsers.add_parser("eval-init")
    eval_init_parser.add_argument("--case", required=True)
    eval_init_parser.add_argument("--run", required=True)
    eval_init_parser.add_argument("--seed-hex", required=True)
    eval_init_parser.add_argument("--protocol", choices=("2.1", "2.2"), default="2.1")
    eval_next_parser = subparsers.add_parser("eval-next")
    eval_next_parser.add_argument("--run", required=True)
    eval_preflight_parser = subparsers.add_parser("eval-preflight")
    eval_preflight_parser.add_argument("--run", required=True)
    eval_preflight_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(eval_preflight_parser)
    eval_submit_parser = subparsers.add_parser("eval-submit")
    eval_submit_parser.add_argument("--run", required=True)
    eval_submit_parser.add_argument("--response", required=True)
    eval_submit_safe_parser = subparsers.add_parser("eval-submit-safe")
    eval_submit_safe_parser.add_argument("--run", required=True)
    eval_submit_safe_parser.add_argument("--response", required=True)
    _add_payload_response_arguments(eval_submit_safe_parser)
    eval_stop_inconclusive_parser = subparsers.add_parser("eval-stop-inconclusive")
    eval_stop_inconclusive_parser.add_argument("--run", required=True)
    eval_stop_inconclusive_parser.add_argument(
        "--reason", required=True, choices=("MECHANICAL_RESPONSE_INVALID",)
    )
    eval_status_parser = subparsers.add_parser("eval-status")
    eval_status_parser.add_argument("--run", required=True)
    eval_verify_parser = subparsers.add_parser("eval-verify")
    eval_verify_parser.add_argument("--run", required=True)
    eval_resume_parser = subparsers.add_parser("eval-resume")
    eval_resume_parser.add_argument("--run", required=True)
    eval_resume_parser.add_argument("--scripted-responses", required=True)
    eval_qualify_init_parser = subparsers.add_parser("eval-qualify-init")
    eval_qualify_init_parser.add_argument("--case", required=True)
    eval_qualify_init_parser.add_argument("--run", required=True)
    eval_qualify_init_parser.add_argument("--nonce-hex", required=True)
    eval_qualify_next_parser = subparsers.add_parser("eval-qualify-next")
    eval_qualify_next_parser.add_argument("--run", required=True)
    eval_qualify_submit_parser = subparsers.add_parser("eval-qualify-submit")
    eval_qualify_submit_parser.add_argument("--run", required=True)
    eval_qualify_submit_parser.add_argument("--response", required=True)
    eval_qualify_status_parser = subparsers.add_parser("eval-qualify-status")
    eval_qualify_status_parser.add_argument("--run", required=True)
    eval_qualify_verify_parser = subparsers.add_parser("eval-qualify-verify")
    eval_qualify_verify_parser.add_argument("--run", required=True)
    eval_gen_init_parser = subparsers.add_parser("eval-gen-init")
    eval_gen_init_parser.add_argument("--input", required=True)
    eval_gen_init_parser.add_argument("--run", required=True)
    eval_gen_init_parser.add_argument("--nonce-hex", required=True)
    eval_gen_next_parser = subparsers.add_parser("eval-gen-next")
    eval_gen_next_parser.add_argument("--run", required=True)
    eval_gen_submit_parser = subparsers.add_parser("eval-gen-submit")
    eval_gen_submit_parser.add_argument("--run", required=True)
    eval_gen_submit_parser.add_argument("--response", required=True)
    eval_gen_status_parser = subparsers.add_parser("eval-gen-status")
    eval_gen_status_parser.add_argument("--run", required=True)
    eval_gen_verify_parser = subparsers.add_parser("eval-gen-verify")
    eval_gen_verify_parser.add_argument("--run", required=True)
    return parser


def _add_payload_response_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider-name", default=argparse.SUPPRESS)
    parser.add_argument("--model-name", default=argparse.SUPPRESS)
    parser.add_argument(
        "--judge-isolation",
        choices=("fresh_context", "scripted_fixture"),
        default=argparse.SUPPRESS,
    )


def _eval_json(value: object) -> None:
    print(canonical_json_bytes(value).decode("utf-8"))


def _safe_evaluation_verification_issues(issues: tuple[str, ...]) -> list[str]:
    normalized: list[str] = []
    for issue in issues:
        if issue.startswith(f"{EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED}:") or issue in (
            _CORE_SCHEMA_FAILURES
        ):
            code = EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED
        elif issue in _CORE_STORAGE_FAILURES or issue.startswith(_CORE_STORAGE_FAILURE_PREFIX):
            code = EVALUATION_STORAGE_PLATFORM_UNSUPPORTED
        else:
            code = EVALUATION_INTEGRITY_INVALID
        if code not in normalized:
            normalized.append(code)
    return normalized or [EVALUATION_INTEGRITY_INVALID]


def _retained_protocol_verifier_nominee(run: Path) -> str | None:
    """Use a bounded marker read only to nominate a canonical verifier."""
    try:
        data = read_evaluation_artifact(
            run, "run-manifest.json", max_bytes=16 * 1024 * 1024
        )
        payload = json.loads(data.decode("utf-8"))
    except (
        EvaluationIntegrityError,
        OSError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ):
        return None
    if type(payload) is not dict:
        return None
    protocol = payload.get("protocol_version")
    if protocol in {"2.0", "2.1", "2.2"}:
        return str(protocol)
    if protocol is None and payload.get("schema_version") in {"1.0", "1.3", "2.0"}:
        return "1.3"
    return None


def _state_payload(state: EvaluationRunState) -> dict[str, object]:
    return state.model_dump(mode="json")


def _eval_exit(state: EvaluationRunState, run: Path) -> int:
    terminal_status = state.terminal_status
    if terminal_status is None:
        return EVAL_EXIT_SUCCESS
    if terminal_status.value in {"case-invalid", "inconclusive"}:
        return EVAL_EXIT_INCONCLUSIVE
    _, result = load_verified_evaluation_run(run)
    return (
        EVAL_EXIT_FAIL
        if any(report.absolute_disposition.value == "FAIL" for report in result.reports)
        else EVAL_EXIT_SUCCESS
    )


def _eval_exit_v2(state: EvaluationRunStateV2, run: Path) -> int:
    if state.terminal_status is None:
        return EVAL_EXIT_SUCCESS
    if state.terminal_status.value == "inconclusive":
        return EVAL_EXIT_INCONCLUSIVE
    _, result = load_verified_v2_run(run)
    if result is None:
        raise EvaluationIntegrityError("EVALUATOR_V2_RESULT_REQUIRED")
    return (
        EVAL_EXIT_FAIL
        if any(report.absolute_disposition.value == "FAIL" for report in result.reports)
        else EVAL_EXIT_SUCCESS
    )


def _eval_exit_v21(state: EvaluationRunStateV21, run: Path) -> int:
    if state.terminal_status is None:
        return EVAL_EXIT_SUCCESS
    if state.terminal_status.value in {"INCONCLUSIVE", "INCONCLUSIVE_MECHANICAL"}:
        return EVAL_EXIT_INCONCLUSIVE
    _, result = load_verified_v21_run(run)
    if result is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_RESULT_REQUIRED")
    return (
        EVAL_EXIT_FAIL
        if any(
            report.reconciliation.absolute_disposition.value == "FAIL"
            for report in result.reports
        )
        else EVAL_EXIT_SUCCESS
    )


def _assert_eval_json_depth(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _EVAL_RESPONSE_MAX_DEPTH:
            raise EvaluationCliInputError(
                "EVALUATION_RESPONSE_INVALID", "The response exceeds the nesting-depth limit."
            )
        if isinstance(current, dict):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)


def _read_canonical_eval_object(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) > _EVAL_RESPONSE_MAX_BYTES:
        raise EvaluationCliInputError(
            "EVALUATION_RESPONSE_INVALID", "The response exceeds the size limit."
        )
    try:
        value = json.loads(data.decode("utf-8"))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationCliInputError(
            "EVALUATION_RESPONSE_INVALID", "The response is not JSON."
        ) from error
    _assert_eval_json_depth(value)
    if data != canonical_json_bytes(value):
        raise EvaluationCliInputError(
            "EVALUATION_RESPONSE_INVALID", "The response must use exact canonical JSON."
        )
    if type(value) is not dict:
        raise EvaluationCliInputError(
            "EVALUATION_RESPONSE_INVALID", "The response must be an object."
        )
    return value


def _read_canonical_eval_response(path: Path) -> JudgeResponse:
    value = _read_canonical_eval_object(path)
    try:
        return JudgeResponse.model_validate(value)
    except ValidationError as error:
        raise EvaluationCliInputError(
            "EVALUATION_RESPONSE_INVALID", _validation_message(error)
        ) from error


def _physical_run_path(value: str) -> Path:
    """Normalize a run physically through only a trusted root-level alias."""
    try:
        expanded = Path(value).expanduser()
        if expanded.anchor == os.sep and len(expanded.parts) > 1:
            root_component = Path(expanded.anchor) / expanded.parts[1]
            if root_component.is_symlink():
                physical_root = Path(os.path.realpath(root_component))
                expanded = physical_root.joinpath(*expanded.parts[2:])
        return Path(os.path.abspath(expanded))
    except (OSError, RuntimeError, ValueError) as error:
        raise EvaluationCliInputError(
            "EVALUATION_INPUT_INVALID", "The run path cannot be normalized safely."
        ) from error


def _read_guarded_eval_object(path: Path) -> dict[str, object] | None:
    """Return one canonical object or a bounded sentinel for guarded submission."""
    try:
        return _read_canonical_eval_object(path)
    except (OSError, RecursionError, UnicodeError, TypeError, ValueError):
        return None


def _readiness_node_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_guarded_readiness_object(path: Path) -> dict[str, object] | None:
    """Read one canonical readiness object through a stable POSIX descriptor chain."""
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if os.name != "posix" or any(not hasattr(os, name) for name in required_flags):
        return None
    try:
        absolute = Path(os.path.abspath(path))
        segments = absolute.parts[1:]
        if not segments:
            return None
        directory_flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        leaf_flags = (
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        root = os.open(os.sep, directory_flags)
        directories: list[
            tuple[int | None, str | None, int, tuple[int, int, int, int, int, int, int]]
        ] = []
        leaf: int | None = None
        try:
            root_metadata = os.fstat(root)
            if not stat.S_ISDIR(root_metadata.st_mode):
                return None
            directories.append((None, None, root, _readiness_node_identity(root_metadata)))
            parent = root
            for segment in segments[:-1]:
                child = os.open(segment, directory_flags, dir_fd=parent)
                registered = False
                try:
                    opened = os.fstat(child)
                    named = os.stat(segment, dir_fd=parent, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or stat.S_ISLNK(named.st_mode)
                        or (opened.st_dev, opened.st_ino)
                        != (named.st_dev, named.st_ino)
                    ):
                        return None
                    directories.append(
                        (parent, segment, child, _readiness_node_identity(opened))
                    )
                    registered = True
                    parent = child
                finally:
                    if not registered:
                        os.close(child)

            leaf = os.open(segments[-1], leaf_flags, dir_fd=parent)
            before = os.fstat(leaf)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or before.st_size > _EVAL_RESPONSE_MAX_BYTES
            ):
                return None
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    leaf,
                    min(1024 * 1024, _EVAL_RESPONSE_MAX_BYTES + 1 - total),
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > _EVAL_RESPONSE_MAX_BYTES:
                    return None
                chunks.append(chunk)
            after = os.fstat(leaf)
            named_leaf = os.stat(segments[-1], dir_fd=parent, follow_symlinks=False)
            if (
                _readiness_node_identity(before) != _readiness_node_identity(after)
                or stat.S_ISLNK(named_leaf.st_mode)
                or (after.st_dev, after.st_ino)
                != (named_leaf.st_dev, named_leaf.st_ino)
            ):
                return None
            for directory_parent, name, descriptor, expected in directories:
                opened = os.fstat(descriptor)
                if _readiness_node_identity(opened) != expected:
                    return None
                if directory_parent is None or name is None:
                    continue
                rebound = os.stat(name, dir_fd=directory_parent, follow_symlinks=False)
                if stat.S_ISLNK(rebound.st_mode) or (opened.st_dev, opened.st_ino) != (
                    rebound.st_dev,
                    rebound.st_ino,
                ):
                    return None
            data = b"".join(chunks)
        finally:
            if leaf is not None:
                os.close(leaf)
            for _, _, descriptor, _ in reversed(directories):
                os.close(descriptor)
            if not directories:
                os.close(root)

        value = json.loads(data.decode("utf-8"))
        _assert_eval_json_depth(value)
        if data != canonical_json_bytes(value) or type(value) is not dict:
            return None
        return value
    except (OSError, RecursionError, UnicodeError, TypeError, ValueError):
        return None


def _read_guarded_v2_response(
    args: argparse.Namespace, run: Path
) -> dict[str, object] | None:
    """Read a full response or deterministically wrap one role-authored payload."""
    value = _read_guarded_eval_object(Path(args.response))
    if value is None:
        return None
    metadata = (
        getattr(args, "provider_name", None),
        getattr(args, "model_name", None),
        getattr(args, "judge_isolation", None),
    )
    if not any(item is not None for item in metadata):
        return value
    if any(item is None for item in metadata):
        return None
    request = next_evaluator_request_v2(run)
    if request is None:
        return None
    provider_name, model_name, judge_isolation = metadata
    return {
        "schema_version": "2.0",
        "operation": request.operation.value,
        "request_fingerprint": request.request_fingerprint,
        "provider_name": provider_name,
        "model_name": model_name,
        "judge_isolation": judge_isolation,
        "payload": value,
    }


def _read_guarded_v21_response(
    args: argparse.Namespace, run: Path
) -> dict[str, object] | None:
    """Read a complete 2.1 response or bind one role payload to the pending call."""
    value = _read_guarded_eval_object(Path(args.response))
    if value is None:
        return None
    metadata = (
        getattr(args, "provider_name", None),
        getattr(args, "model_name", None),
        getattr(args, "judge_isolation", None),
    )
    if not any(item is not None for item in metadata):
        return value
    if any(item is None for item in metadata):
        return None
    request = next_evaluator_request_v21(run)
    if request is None:
        return None
    provider_name, model_name, judge_isolation = metadata
    return {
        "schema_version": "2.1",
        "operation": request.operation.value,
        "request_fingerprint": request.request_fingerprint,
        "provider_name": provider_name,
        "model_name": model_name,
        "judge_isolation": judge_isolation,
        "payload": value,
    }


def _schema_preflight_result(
    request: JudgeRequest | None,
) -> EvaluationPreflightResult:
    issue = EvaluationPreflightIssue(
        code="EVALUATION_RESPONSE_SCHEMA_INVALID",
        message="The response does not satisfy the canonical response schema.",
    )
    return EvaluationPreflightResult(
        ok=False,
        operation=None if request is None else request.operation,
        request_fingerprint=None if request is None else request.request_fingerprint,
        issues=[issue],
        diagnostic_fingerprint=(
            None
            if request is None
            else sha256_digest(
                canonical_json_bytes(
                    {
                        "issues": [issue.model_dump(mode="json")],
                        "operation": request.operation.value,
                        "request_fingerprint": request.request_fingerprint,
                    }
                )
            )
        ),
    )


def _no_pending_preflight_result() -> EvaluationPreflightResult:
    return EvaluationPreflightResult(
        ok=False,
        operation=None,
        request_fingerprint=None,
        issues=[
            EvaluationPreflightIssue(
                code="EVALUATION_NO_PENDING_REQUEST",
                message="The evaluation run has no pending request.",
            )
        ],
    )


def _run_v1_eval_command(args: argparse.Namespace, run: Path) -> int:
    try:
        if args.command == "eval-next":
            request = next_judge_request(run)
            if request is None:
                state = resume_evaluation(run)
                _eval_json(None)
                return _eval_exit(state, run)
            _eval_json(request.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-preflight":
            request = next_judge_request(run)
            if request is None:
                _eval_json(_no_pending_preflight_result().model_dump(mode="json"))
                return EVAL_EXIT_INPUT
            try:
                response = _read_canonical_eval_response(Path(args.response))
            except EvaluationCliInputError as error:
                if error.code != "EVALUATION_RESPONSE_INVALID":
                    raise
                result = _schema_preflight_result(request)
            else:
                result = preflight_judge_response(run, response)
            _eval_json(result.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS if result.ok else EVAL_EXIT_INPUT
        if args.command == "eval-submit":
            response = _read_canonical_eval_response(Path(args.response))
            request = next_judge_request(run)
            if request is None or (
                response.operation is not request.operation
                or response.request_fingerprint != request.request_fingerprint
            ):
                raise EvaluationCliInputError(
                    "EVALUATION_RESPONSE_INVALID",
                    "The response does not bind the pending request.",
                )
            state = submit_judge_response(run, response)
            _eval_json(_state_payload(state))
            return _eval_exit(state, run)
        if args.command == "eval-submit-safe":
            request = next_judge_request(run)
            if request is None:
                guarded_result = GuardedSubmissionResult(
                    accepted=False,
                    preflight=_no_pending_preflight_result(),
                )
            else:
                value = _read_guarded_eval_object(Path(args.response))
                if value is None:
                    guarded_result = GuardedSubmissionResult(
                        accepted=False,
                        preflight=_schema_preflight_result(request),
                    )
                else:
                    try:
                        response = JudgeResponse.model_validate(value)
                    except ValidationError:
                        guarded_result = GuardedSubmissionResult(
                            accepted=False,
                            preflight=_schema_preflight_result(request),
                        )
                    else:
                        guarded_result = guarded_submit_judge_response(run, response)
            _eval_json(guarded_result.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS if guarded_result.accepted else EVAL_EXIT_INPUT
        if args.command == "eval-status":
            state = resume_evaluation(run)
            _eval_json(_state_payload(state))
            return _eval_exit(state, run)
        verification = verify_evaluation_run(run)
        if not verification.valid:
            _eval_json(
                {"ok": False, "issues": _safe_evaluation_verification_issues(verification.issues)}
            )
            return EVAL_EXIT_INTEGRITY
        state = resume_evaluation(run)
        _eval_json(
            {"ok": True, "manifest_root": verification.root_hash, "state": _state_payload(state)}
        )
        return _eval_exit(state, run)
    except EvaluationSourceParityUnprovenError as error:
        _write_error("EVALUATION_SOURCE_PARITY_UNPROVEN", str(error))
        return EVAL_EXIT_INCONCLUSIVE
    except (generation.GenerationIntegrityError, EvaluationIntegrityError):
        raise
    except (TypeError, ValueError) as error:
        raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error


def _v2_preflight_payload(preflight: V2ResponsePreflight) -> dict[str, object]:
    return {"diagnostics": list(preflight.diagnostics), "valid": preflight.valid}


def _v2_guarded_payload(result: GuardedSubmissionResultV2) -> dict[str, object]:
    accepted = result.accepted
    preflight = result.preflight
    state = result.state
    payload: dict[str, object] = {
        "accepted": accepted,
        "preflight": _v2_preflight_payload(preflight),
    }
    if state is not None:
        payload["state"] = state.model_dump(mode="json")
    return payload


def _v21_preflight_payload(preflight: V21ResponsePreflight) -> dict[str, object]:
    return {"diagnostics": list(preflight.diagnostics), "valid": preflight.valid}


def _v21_guarded_payload(result: GuardedSubmissionResultV21) -> dict[str, object]:
    payload: dict[str, object] = {
        "accepted": result.accepted,
        "preflight": _v21_preflight_payload(result.preflight),
    }
    if result.state is not None:
        payload["state"] = result.state.model_dump(mode="json")
    return payload


def _v22_preflight_payload(preflight: V22ResponsePreflight) -> dict[str, object]:
    return {"diagnostics": list(preflight.diagnostics), "valid": preflight.valid}


def _v22_guarded_payload(result: GuardedSubmissionResultV22) -> dict[str, object]:
    payload: dict[str, object] = {
        "accepted": result.accepted,
        "preflight": _v22_preflight_payload(result.preflight),
    }
    if result.state is not None:
        payload["state"] = result.state.model_dump(mode="json")
    return payload


def _readiness_pending_operation(
    request: ReadinessEvaluatorRequestV1 | None,
) -> dict[str, object] | None:
    """Project one pending request without identifiers, text, or paths."""
    if request is None:
        return None
    lane_value = request.payload.get("lane")
    lane = lane_value if type(lane_value) is int and lane_value in {1, 2} else None
    fragment_class = {
        "baseline_locked_grade": "ordinary_batch",
        "baseline_locked_contested_grade": "contested_requirement",
        "safety_review": "safety_lane",
        "safety_referee": "safety_dispute",
    }[request.operation.value]
    return {
        "fragment_class": fragment_class,
        "lane": lane,
        "operation": request.operation.value,
    }


def _readiness_historical_fields(
    context: VerifiedReadinessContextV1,
) -> dict[str, object]:
    result = context.result
    if result is not None and result.historical_v22_strict_disposition is not None:
        return {
            "historical_v22_cross_check_status": (
                result.historical_v22_cross_check_status.value
            ),
            "historical_v22_strict_disposition": (
                result.historical_v22_strict_disposition.value
            ),
        }
    historical = context.inputs.historical_v22
    if historical is None:
        return {}
    if not historical.baseline_comparable:
        status: str | None = "BASELINE_NOT_COMPARABLE"
    elif not historical.report_comparable:
        status = "REPORT_NOT_COMPARABLE"
    else:
        status = None
    return {
        "historical_v22_cross_check_status": status,
        "historical_v22_strict_disposition": historical.strict_disposition.value,
    }


def _readiness_status_payload(
    context: VerifiedReadinessContextV1,
    *,
    engine_paused: bool = False,
) -> dict[str, object]:
    """Return the allowlisted public readiness status projection."""
    result = context.result
    payload: dict[str, object] = {
        "baseline_locked_strict_equivalent_disposition": (
            None
            if result is None
            else result.baseline_locked_strict_equivalent_disposition.value
        ),
        "delivery_readiness": None if result is None else result.delivery_readiness.value,
        "engine_paused": engine_paused,
        "manifest_fingerprint": context.manifest.manifest_fingerprint,
        "pending_operation": _readiness_pending_operation(context.pending_request),
        "protocol_version": READINESS_PROTOCOL_V1,
    }
    payload.update(_readiness_historical_fields(context))
    return payload


def render_readiness_status_human_v1(payload: dict[str, object]) -> str:
    """Render only the three distinct attorney-facing readiness dispositions."""
    required = {
        "baseline_locked_strict_equivalent_disposition",
        "delivery_readiness",
        "engine_paused",
        "manifest_fingerprint",
        "pending_operation",
        "protocol_version",
    }
    historical = {
        "historical_v22_cross_check_status",
        "historical_v22_strict_disposition",
    }
    keys = set(payload)
    if not (keys == required or keys == required | historical):
        raise ValueError("readiness status has an unexpected shape")
    fresh = payload["baseline_locked_strict_equivalent_disposition"]
    delivery = payload["delivery_readiness"]
    if historical <= keys:
        historical_disposition = payload["historical_v22_strict_disposition"]
        cross_check = payload["historical_v22_cross_check_status"]
        suffix = {
            None: " (cross-check pending)",
            "BASELINE_NOT_COMPARABLE": " (baseline not comparable)",
            "REPORT_NOT_COMPARABLE": " (report not comparable)",
            "MATCH": " (cross-check matches)",
            "DISPOSITION_DIFFERS": " (cross-check differs)",
        }.get(cast(str | None, cross_check))
        if suffix is None:
            raise ValueError("readiness status has an invalid historical cross-check")
        history_line = (
            "Historical Protocol 2.2 strict disposition: "
            f"{historical_disposition}{suffix}"
        )
    else:
        history_line = "Historical Protocol 2.2 strict disposition: not supplied"
    return "\n".join(
        (
            f"Baseline-locked strict-equivalent: {fresh if fresh is not None else 'pending'}",
            history_line,
            f"Delivery readiness: {delivery if delivery is not None else 'pending'}",
        )
    )


def _write_readiness_status(payload: dict[str, object]) -> None:
    if sys.stdout.isatty():
        print(render_readiness_status_human_v1(payload))
    else:
        _eval_json(payload)


def _readiness_preflight_payload(result: GuardedReadinessSubmissionResultV1) -> dict[str, object]:
    diagnostics = (
        [] if result.accepted else [READINESS_EXTERNAL_RESPONSE_INVALID]
    )
    return {"diagnostics": diagnostics, "valid": result.accepted}


def _readiness_guarded_payload(
    result: GuardedReadinessSubmissionResultV1,
    context: VerifiedReadinessContextV1 | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "accepted": result.accepted,
        "preflight": _readiness_preflight_payload(result),
    }
    if result.accepted:
        if context is None:
            raise EvaluationIntegrityError("READINESS_ACCEPTED_STATE_REQUIRED")
        payload["status"] = _readiness_status_payload(context)
    return payload


def _read_guarded_readiness_response(
    args: argparse.Namespace,
    run: Path,
) -> object:
    """Read a strict response or compile and bind one role-authored inner payload."""
    value = _read_guarded_readiness_object(Path(args.response))
    if value is None:
        return None
    metadata = (
        getattr(args, "provider_name", None),
        getattr(args, "model_name", None),
        getattr(args, "judge_isolation", None),
    )
    if not any(item is not None for item in metadata):
        return value
    if any(item is None for item in metadata):
        return None
    request = next_readiness_request_v1(run)
    if request is None:
        return None
    provider_name, model_name, judge_isolation = cast(tuple[str, str, str], metadata)
    try:
        provenance = ReadinessEvaluatorProvenanceV1(
            provider_name=provider_name,
            model_name=model_name,
            judge_isolation=cast(
                Literal["fresh_context", "scripted_fixture"], judge_isolation
            ),
        )
    except (TypeError, ValidationError, ValueError):
        return None
    compiled = compile_readiness_draft_v1(request, value, provenance)
    return compiled.response if isinstance(compiled, CompiledReadinessDraftV1) else None


def _readiness_context_exit_code(
    context: VerifiedReadinessContextV1,
    *,
    engine_paused: bool = False,
) -> int:
    if engine_paused:
        return EVAL_EXIT_ENGINE_PAUSED
    if context.manifest.terminal_status is None:
        return EVAL_EXIT_SUCCESS
    return readiness_exit_code_v1(context.result, paused=False)


def _readiness_verification_payload(
    context: VerifiedReadinessContextV1 | None,
    *,
    valid: bool,
    issue_codes: tuple[str, ...],
) -> dict[str, object]:
    result: DeliveryReadinessResultV1 | None = None if context is None else context.result
    payload: dict[str, object] = {
        "baseline_locked_strict_equivalent_disposition": (
            None
            if result is None
            else result.baseline_locked_strict_equivalent_disposition.value
        ),
        "delivery_readiness": None if result is None else result.delivery_readiness.value,
        "issue_codes": list(issue_codes),
        "manifest_fingerprint": (
            None if context is None else context.manifest.manifest_fingerprint
        ),
        "ok": valid,
        "protocol_version": READINESS_PROTOCOL_V1,
        "result_fingerprint": None if result is None else result.result_fingerprint,
        "root_hash": None if context is None else context.manifest.root_hash,
        "strict_equivalent_scoring_contract_fingerprint": (
            None
            if context is None
            else context.manifest.strict_equivalent_scoring_contract_fingerprint
        ),
    }
    if context is not None:
        payload.update(_readiness_historical_fields(context))
    return payload


def _eval_exit_v22(state: EvaluationRunStateV22, run: Path) -> int:
    if state.terminal_status is None:
        return EVAL_EXIT_SUCCESS
    _, result = load_verified_v22_run(run)
    if result is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_RESULT_REQUIRED")
    if result.terminal_status.value == "INCONCLUSIVE":
        return EVAL_EXIT_INCONCLUSIVE
    return (
        EVAL_EXIT_FAIL
        if any(
            report.sensitivity.absolute_disposition.value == "FAIL"
            for report in result.reports
        )
        else EVAL_EXIT_SUCCESS
    )


def _run_v2_eval_command(args: argparse.Namespace, run: Path) -> int:
    try:
        if args.command == "eval-next":
            request = next_evaluator_request_v2(run)
            if request is None:
                state = resume_evaluation_v2(run)
                _eval_json(None)
                return _eval_exit_v2(state, run)
            _eval_json(request.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-preflight":
            value = _read_guarded_v2_response(args, run)
            preflight = preflight_evaluator_response_v2(run, value)
            _eval_json(_v2_preflight_payload(preflight))
            return EVAL_EXIT_SUCCESS if preflight.valid else EVAL_EXIT_INPUT
        if args.command == "eval-submit":
            response = _read_canonical_eval_object(Path(args.response))
            state = submit_evaluator_response_v2(run, response)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v2(state, run)
        if args.command == "eval-submit-safe":
            value = _read_guarded_v2_response(args, run)
            guarded = guarded_submit_evaluator_response_v2(run, value)
            _eval_json(_v2_guarded_payload(guarded))
            return EVAL_EXIT_SUCCESS if guarded.accepted else EVAL_EXIT_INPUT
        if args.command == "eval-stop-inconclusive":
            if next_evaluator_request_v2(run) is None:
                raise EvaluationCliInputError(
                    "EVALUATION_INPUT_INVALID", "The evaluation run has no pending request."
                )
            state = stop_evaluation_v2_inconclusive(run, args.reason)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v2(state, run)
        if args.command == "eval-status":
            state = resume_evaluation_v2(run)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v2(state, run)
        verification = verify_v2_run(run)
        if not verification.valid:
            _eval_json(
                {"ok": False, "issues": _safe_evaluation_verification_issues(verification.issues)}
            )
            return EVAL_EXIT_INTEGRITY
        state = resume_evaluation_v2(run)
        _eval_json(
            {
                "ok": True,
                "manifest_root": verification.root_hash,
                "state": state.model_dump(mode="json"),
            }
        )
        return _eval_exit_v2(state, run)
    except EvaluationIntegrityError:
        raise
    except (TypeError, ValueError) as error:
        raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error


def _run_v21_eval_command(args: argparse.Namespace, run: Path) -> int:
    try:
        if args.command == "eval-next":
            request = next_evaluator_request_v21(run)
            if request is None:
                state = resume_evaluation_v21(run)
                _eval_json(None)
                return _eval_exit_v21(state, run)
            _eval_json(request.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-preflight":
            value = _read_guarded_v21_response(args, run)
            preflight = preflight_evaluator_response_v21(run, value)
            _eval_json(_v21_preflight_payload(preflight))
            return EVAL_EXIT_SUCCESS if preflight.valid else EVAL_EXIT_INPUT
        if args.command == "eval-submit":
            response = _read_canonical_eval_object(Path(args.response))
            state = submit_evaluator_response_v21(run, response)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v21(state, run)
        if args.command == "eval-submit-safe":
            value = _read_guarded_v21_response(args, run)
            guarded = guarded_submit_evaluator_response_v21(run, value)
            _eval_json(_v21_guarded_payload(guarded))
            return EVAL_EXIT_SUCCESS if guarded.accepted else EVAL_EXIT_INPUT
        if args.command == "eval-stop-inconclusive":
            if next_evaluator_request_v21(run) is None:
                raise EvaluationCliInputError(
                    "EVALUATION_INPUT_INVALID", "The evaluation run has no pending request."
                )
            state = stop_evaluation_v21_inconclusive(run, args.reason)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v21(state, run)
        if args.command == "eval-status":
            state = resume_evaluation_v21(run)
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v21(state, run)
        verification = verify_v21_run(run)
        if not verification.valid:
            _eval_json(
                {"ok": False, "issues": _safe_evaluation_verification_issues(verification.issues)}
            )
            return EVAL_EXIT_INTEGRITY
        state = resume_evaluation_v21(run)
        _eval_json(
            {
                "ok": True,
                "manifest_root": verification.root_hash,
                "state": state.model_dump(mode="json"),
            }
        )
        return _eval_exit_v21(state, run)
    except EvaluationIntegrityError:
        raise
    except (TypeError, ValueError) as error:
        raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error


def _run_v22_eval_command(args: argparse.Namespace, run: Path) -> int:
    try:
        if args.command == "eval-next":
            request = next_evaluator_request_v22(run)
            if request is None:
                state = resume_evaluation_v22(run)
                _eval_json(None)
                return _eval_exit_v22(state, run)
            _eval_json(request.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-preflight":
            value = _read_guarded_eval_object(Path(args.response))
            preflight = preflight_evaluator_response_v22(run, value)
            _eval_json(_v22_preflight_payload(preflight))
            return EVAL_EXIT_SUCCESS if preflight.valid else EVAL_EXIT_INPUT
        if args.command == "eval-submit":
            value = _read_guarded_eval_object(Path(args.response))
            try:
                state = submit_evaluator_response_v22(run, value)
            except (TypeError, ValueError) as error:
                raise EvaluationCliInputError(
                    "EXTERNAL_RESPONSE_INVALID",
                    "The strict response does not bind the pending request.",
                ) from error
            _eval_json(state.model_dump(mode="json"))
            return _eval_exit_v22(state, run)
        if args.command == "eval-submit-safe":
            value = _read_guarded_eval_object(Path(args.response))
            guarded = guarded_submit_evaluator_response_v22(run, value)
            _eval_json(_v22_guarded_payload(guarded))
            return EVAL_EXIT_SUCCESS if guarded.accepted else EVAL_EXIT_INPUT
        if args.command == "eval-stop-inconclusive":
            raise EvaluationCliInputError(
                "EVALUATION_MUTATION_UNSUPPORTED",
                "Protocol 2.2 has no mechanical terminalization command.",
            )
        if args.command == "eval-resume":
            responses = _scripted_drafts_from_fixture(Path(args.scripted_responses))
            _probe_resumed_scripted_v22_run(run, responses)
            evaluator = _ScriptedFixtureDraftEvaluatorV22(responses)
            try:
                outcome = asyncio.run(continue_evaluation_v22(run, evaluator))
            except (EvaluationIntegrityError, _ScriptedDraftFixtureError):
                raise
            except Exception:
                resume_evaluation_v22(run)
                _eval_json(
                    {
                        "error": "evaluation_engine_paused",
                        "ok": False,
                        "pending_call": _v22_nonterminal_payload(run)["pending_call"],
                    }
                )
                return EVAL_EXIT_ENGINE_PAUSED
            evaluator.assert_exhausted()
            _eval_json(
                _v22_outcome_payload(
                    outcome,
                    run,
                    judge_mode="local-scripted-fixture",
                )
            )
            return outcome.exit_code
        if args.command == "eval-status":
            state = resume_evaluation_v22(run)
            if state.terminal_status is None:
                _eval_json(_v22_nonterminal_payload(run))
            else:
                _, result = load_verified_v22_run(run)
                if result is None:
                    raise EvaluationIntegrityError("EVALUATOR_V22_RESULT_REQUIRED")
                _eval_json(_v22_result_payload(result, run, judge_mode="status-only"))
            return _eval_exit_v22(state, run)
        verification = verify_v22_run(run)
        if not verification.valid:
            _eval_json(
                {"ok": False, "issues": _safe_evaluation_verification_issues(verification.issues)}
            )
            return EVAL_EXIT_INTEGRITY
        state = resume_evaluation_v22(run)
        if state.terminal_status is None:
            _eval_json(_v22_nonterminal_payload(run))
        else:
            _, result = load_verified_v22_run(run)
            if result is None:
                raise EvaluationIntegrityError("EVALUATOR_V22_RESULT_REQUIRED")
            _eval_json(_v22_result_payload(result, run, judge_mode="verification-only"))
        return _eval_exit_v22(state, run)
    except EvaluationCliInputError:
        raise
    except EvaluationIntegrityError:
        raise
    except (TypeError, ValueError) as error:
        raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error


def _run_eval_command(args: argparse.Namespace) -> int:
    if args.command == "eval-init":
        try:
            run = _physical_run_path(args.run)
            # Initialization normally owns a new empty directory. Explicit
            # v2.2 verifies a detected retained root before refusing it. The
            # default v2.1 path keeps its historical detection-only behavior.
            if args.protocol == "2.2":
                protocol = _verified_protocol_for_v22_initialization(run)
                if protocol in {"1.3", "2.0", "2.1"}:
                    raise EvaluationCliInputError(
                        "EVALUATION_LEGACY_READ_ONLY",
                        f"Protocol {protocol} evaluation runs are read-only.",
                    )
            elif run.exists():
                try:
                    protocol = detect_evaluation_protocol(run)
                except (EvaluationIntegrityError, OSError, TypeError, ValueError):
                    protocol = None
                if protocol in {"1.3", "2.0", "2.1"}:
                    raise EvaluationCliInputError(
                        "EVALUATION_LEGACY_READ_ONLY",
                        f"Protocol {protocol} evaluation runs are read-only.",
                    )
            case_path = Path(args.case)
            case, capsule_paths = _case_and_capsules_from_fixture(
                case_path, root=case_path.parent
            )
            if args.protocol == "2.2":
                state_v22 = initialize_evaluation_v22(
                    case,
                    run,
                    seed_hex=args.seed_hex,
                    generation_capsule_paths=capsule_paths,
                )
                _eval_json(state_v22.model_dump(mode="json"))
            else:
                state_v21 = initialize_evaluation_v21(
                    case,
                    run,
                    seed_hex=args.seed_hex,
                    generation_capsule_paths=capsule_paths,
                )
                _eval_json(state_v21.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        except EvaluationCliInputError:
            raise
        except EvaluationIntegrityError as error:
            if args.protocol == "2.2":
                raise
            raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error
        except (TypeError, ValueError) as error:
            raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error

    run = _physical_run_path(args.run)
    try:
        protocol = detect_evaluation_protocol(run)
    except (EvaluationIntegrityError, OSError, TypeError, ValueError) as error:
        protocol = _retained_protocol_verifier_nominee(run)
        if protocol is None:
            raise EvaluationCliInputError(
                "EVALUATION_PROTOCOL_UNSUPPORTED",
                "The evaluation run protocol is unsupported.",
            ) from error
        if protocol == "1.3":
            verification = verify_evaluation_run(run)
        elif protocol == "2.0":
            verification = verify_v2_run(run)
        elif protocol == "2.1":
            verification = verify_v21_run(run)
        else:
            verification = verify_v22_run(run)
        if not verification.valid:
            if args.command in {"eval-verify", "eval-resume"}:
                _eval_json(
                    {
                        "ok": False,
                        "issues": _safe_evaluation_verification_issues(
                            verification.issues
                        ),
                    }
                )
                return EVAL_EXIT_INTEGRITY
            raise EvaluationIntegrityError("EVALUATION_RETAINED_RUN_INVALID") from error
    if protocol == "2.2":
        return _run_v22_eval_command(args, run)
    if protocol == "2.1":
        if args.command == "eval-resume":
            raise EvaluationCliInputError(
                "EVALUATION_LEGACY_READ_ONLY",
                "Protocol 2.1 evaluation runs cannot use Protocol 2.2 resume.",
            )
        return _run_v21_eval_command(args, run)
    if protocol in {"1.3", "2.0"}:
        if args.command not in {"eval-status", "eval-verify"}:
            raise EvaluationCliInputError(
                "EVALUATION_LEGACY_READ_ONLY", f"Protocol {protocol} evaluation runs are read-only."
            )
        if protocol == "2.0":
            return _run_v2_eval_command(args, run)
        return _run_v1_eval_command(args, run)
    raise EvaluationCliInputError(
        "EVALUATION_PROTOCOL_UNSUPPORTED", "The evaluation run protocol is unsupported."
    )


def _run_qualification_command(args: argparse.Namespace) -> int:
    run = _physical_run_path(args.run)
    try:
        if args.command == "eval-qualify-init":
            case_path = Path(args.case)
            try:
                case = _qualification_case_from_fixture(case_path, root=case_path.parent)
            except (TypeError, ValueError) as error:
                raise EvaluationCliInputError(
                    "EVALUATION_INPUT_INVALID",
                    "The qualification case fixture is invalid.",
                ) from error
            payload: object = initialize_case_qualification(
                case,
                run,
                nonce_hex=args.nonce_hex,
            )
        elif args.command == "eval-qualify-next":
            payload = next_qualification_request(run)
        elif args.command == "eval-qualify-submit":
            request = next_qualification_request(run)
            if request is None:
                submission = QualificationSubmissionResult(
                    accepted=False,
                    preflight=_no_pending_preflight_result(),
                )
            else:
                response = _read_guarded_eval_object(Path(args.response))
                if response is None:
                    submission = QualificationSubmissionResult(
                        accepted=False,
                        preflight=_schema_preflight_result(request),
                    )
                else:
                    submission = guarded_submit_case_qualification(run, response)
            payload = submission
            _eval_json(submission.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS if submission.accepted else EVAL_EXIT_INPUT
        elif args.command == "eval-qualify-status":
            payload = resume_case_qualification(run)
        else:
            verification = verify_case_qualification(run)
            payload = verification
            _eval_json(verification.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS if verification.valid else EVAL_EXIT_INTEGRITY
        if hasattr(payload, "model_dump"):
            _eval_json(payload.model_dump(mode="json"))
        else:
            _eval_json(payload)
        return EVAL_EXIT_SUCCESS
    except (EvaluationCliInputError, EvaluationIntegrityError):
        raise
    except (TypeError, ValueError) as error:
        raise EvaluationCliInputError("EVALUATION_INPUT_INVALID", str(error)) from error


def _run_baseline_command(args: argparse.Namespace) -> int:
    """Run the report-blind baseline lifecycle without legal-grade exit codes."""
    run = _physical_run_path(args.run)
    try:
        if args.command == "eval-baseline-init":
            prior_values = getattr(args, "prior_baseline", None) or []
            if type(prior_values) is not list or any(
                type(value) is not str for value in prior_values
            ):
                raise EvaluationCliInputError(
                    "BASELINE_INPUT_INVALID", "The baseline ancestry is invalid."
                )
            prior_paths = tuple(_physical_run_path(value) for value in prior_values)
            correction_value = getattr(args, "correction", None)
            initialize_baseline_v1(
                Path(args.input),
                run,
                nonce_hex=args.nonce_hex,
                prior_baseline_path=prior_paths[-1] if prior_paths else None,
                correction_path=(
                    None if correction_value is None else Path(correction_value)
                ),
                prior_ancestry=prior_paths[:-1],
            )
            _eval_json(
                baseline_status_payload_v1(
                    run,
                    prior_baseline_path=prior_paths[-1] if prior_paths else None,
                    prior_ancestry=prior_paths[:-1],
                )
            )
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-next":
            request = next_baseline_request_v1(run)
            _eval_json(None if request is None else request.model_dump(mode="json"))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-submit-safe":
            payload = _read_guarded_eval_object(Path(args.response))
            result = guarded_submit_baseline_response_v1(
                run,
                payload,
                provider_name=args.provider_name,
                model_name=args.model_name,
                judge_isolation=args.judge_isolation,
            )
            if not result.accepted:
                raise EvaluationCliInputError(
                    BASELINE_EXTERNAL_RESPONSE_INVALID,
                    "The baseline response is invalid.",
                )
            _eval_json(baseline_status_payload_v1(run))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-baseline-status":
            _eval_json(baseline_status_payload_v1(run))
            return EVAL_EXIT_SUCCESS
        verification = verify_baseline_run(run)
        _eval_json(
            {
                "issues": list(verification.issues),
                "ok": verification.valid,
                "protocol_version": BASELINE_PROTOCOL_V1,
            }
        )
        return EVAL_EXIT_SUCCESS if verification.valid else EVAL_EXIT_INTEGRITY
    except (EvaluationCliInputError, EvaluationIntegrityError):
        raise
    except BaselineInputError as error:
        raise EvaluationCliInputError(
            "BASELINE_INPUT_INVALID", "The baseline input is invalid."
        ) from error
    except (OSError, RecursionError, TypeError, UnicodeError, ValidationError, ValueError) as error:
        raise EvaluationCliInputError(
            "BASELINE_INPUT_INVALID", "The baseline command input is invalid."
        ) from error


def _run_readiness_command(args: argparse.Namespace) -> int:
    """Run the opt-in readiness companion without changing retained evaluation commands."""
    run = _physical_run_path(args.run)
    try:
        if args.command == "eval-readiness-init":
            historical_run_value = getattr(args, "historical_v22_run", None)
            historical_label = getattr(args, "historical_report_label", None)
            if (historical_run_value is None) != (historical_label is None):
                raise EvaluationCliInputError(
                    "READINESS_INPUT_INVALID",
                    "Historical Protocol 2.2 options must be supplied together.",
                )
            initialize_readiness_v1(
                run,
                baseline_run_dir=_physical_run_path(args.baseline_run),
                qualification_run_dir=_physical_run_path(args.qualification_run),
                generation_run_dir=_physical_run_path(args.generation_run),
                validation_receipt_path=_physical_run_path(args.validation_receipt),
                historical_v22_run_dir=(
                    None
                    if historical_run_value is None
                    else _physical_run_path(historical_run_value)
                ),
                historical_anonymous_label=cast(
                    Literal["A", "B"] | None, historical_label
                ),
            )
            context = load_verified_readiness_context_v1(run)
            _eval_json(_readiness_status_payload(context))
            return EVAL_EXIT_SUCCESS
        if args.command == "eval-readiness-next":
            request = next_readiness_request_v1(run)
            _eval_json(None if request is None else request.model_dump(mode="json"))
            context = load_verified_readiness_context_v1(run)
            return _readiness_context_exit_code(context)
        if args.command == "eval-readiness-submit-safe":
            response = _read_guarded_readiness_response(args, run)
            guarded = guarded_submit_readiness_response_v1(run, response)
            submitted_context: VerifiedReadinessContextV1 | None = (
                load_verified_readiness_context_v1(run) if guarded.accepted else None
            )
            _eval_json(_readiness_guarded_payload(guarded, submitted_context))
            if not guarded.accepted:
                return EVAL_EXIT_INPUT
            assert submitted_context is not None
            return _readiness_context_exit_code(submitted_context)
        if args.command == "eval-readiness-status":
            context = load_verified_readiness_context_v1(run)
            _write_readiness_status(_readiness_status_payload(context))
            return _readiness_context_exit_code(context)
        verification = verify_readiness_run_v1(run)
        if not verification.valid:
            _eval_json(
                _readiness_verification_payload(
                    None,
                    valid=False,
                    issue_codes=verification.issues,
                )
            )
            return EVAL_EXIT_INTEGRITY
        context = load_verified_readiness_context_v1(run)
        _eval_json(
            _readiness_verification_payload(
                context,
                valid=True,
                issue_codes=verification.issues,
            )
        )
        return _readiness_context_exit_code(context)
    except (EvaluationCliInputError, EvaluationIntegrityError):
        raise
    except ReadinessInputError as error:
        raise EvaluationCliInputError(
            "READINESS_INPUT_INVALID", "The readiness input is invalid."
        ) from error
    except (OSError, RecursionError, TypeError, UnicodeError, ValidationError, ValueError) as error:
        raise EvaluationCliInputError(
            "READINESS_INPUT_INVALID", "The readiness command input is invalid."
        ) from error


def _generation_json(value: object) -> None:
    print(generation.canonical_json_bytes(value).decode("utf-8"))


def _run_generation_command(args: argparse.Namespace) -> int:
    try:
        run = Path(args.run)
        payload: object
        if args.command == "eval-gen-init":
            payload = generation.initialize_generation(
                Path(args.input), run, nonce_hex=args.nonce_hex
            )
        elif args.command == "eval-gen-next":
            payload = generation.next_generation_request(run)
        elif args.command == "eval-gen-submit":
            payload = generation.submit_generation_response(run, Path(args.response))
        elif args.command == "eval-gen-status":
            payload = generation.generation_status(run)
        else:
            payload = generation.verify_generation_capsule(run)
        _generation_json(payload)
        return EVAL_EXIT_SUCCESS
    except generation.GenerationInputError as error:
        raise EvaluationCliInputError("GENERATION_INPUT_INVALID", str(error)) from error


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command.startswith("eval-baseline-"):
            return _run_baseline_command(args)
        if args.command.startswith("eval-readiness-"):
            return _run_readiness_command(args)
        if args.command.startswith("eval-gen-"):
            return _run_generation_command(args)
        if args.command.startswith("eval-qualify-"):
            return _run_qualification_command(args)
        return _run_eval_command(args)
    except EvaluationCliInputError as error:
        _write_error(error.code, str(error))
        return EVAL_EXIT_INPUT
    except FileNotFoundError:
        _write_error("INPUT_NOT_FOUND", "A required input file was not found.")
        return EVAL_EXIT_INPUT
    except EvaluationIntegrityError:
        _write_error("EVALUATION_INTEGRITY_INVALID", "The evaluation run failed integrity checks.")
        return EVAL_EXIT_INTEGRITY
    except generation.GenerationIntegrityError as error:
        code = (
            generation.GENERATION_STORAGE_PLATFORM_UNSUPPORTED
            if str(error).startswith(generation.GENERATION_STORAGE_PLATFORM_UNSUPPORTED)
            else generation.GENERATION_INTEGRITY_INVALID
        )
        _write_error(code, "The generation capsule failed integrity checks.")
        return EVAL_EXIT_INTEGRITY
    except Exception as error:
        _write_error(
            "ENGINE_FAILURE",
            f"The deterministic engine could not complete ({type(error).__name__}).",
        )
        return EVAL_EXIT_INCONCLUSIVE


if __name__ == "__main__":
    raise SystemExit(main())
