#!/usr/bin/env python3
"""Dependency-minimal entry point for the full attorney evaluation runtime.

This module intentionally imports only the evaluation substrate.  The combined
``harvest_skill.py`` runner dispatches here before importing the research and
briefing stack, so an evaluation install is not coupled to unrelated model
surfaces.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Never

from pydantic import ValidationError

from regulatory_harvest.evaluation import attorney_generation as generation
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
    load_verified_evaluation_run,
    verify_evaluation_run,
)
from regulatory_harvest.evaluation.attorney_cli import (
    _case_and_capsules_from_fixture,
    _qualification_case_from_fixture,
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
from regulatory_harvest.evaluation.attorney_qualification import (
    guarded_submit_case_qualification,
    initialize_case_qualification,
    next_qualification_request,
    resume_case_qualification,
    verify_case_qualification,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    EvaluationSourceParityUnprovenError,
    guarded_submit_judge_response,
    initialize_evaluation,
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
    eval_init_parser = subparsers.add_parser("eval-init")
    eval_init_parser.add_argument("--case", required=True)
    eval_init_parser.add_argument("--run", required=True)
    eval_init_parser.add_argument("--seed-hex", required=True)
    eval_next_parser = subparsers.add_parser("eval-next")
    eval_next_parser.add_argument("--run", required=True)
    eval_preflight_parser = subparsers.add_parser("eval-preflight")
    eval_preflight_parser.add_argument("--run", required=True)
    eval_preflight_parser.add_argument("--response", required=True)
    eval_submit_parser = subparsers.add_parser("eval-submit")
    eval_submit_parser.add_argument("--run", required=True)
    eval_submit_parser.add_argument("--response", required=True)
    eval_submit_safe_parser = subparsers.add_parser("eval-submit-safe")
    eval_submit_safe_parser.add_argument("--run", required=True)
    eval_submit_safe_parser.add_argument("--response", required=True)
    eval_status_parser = subparsers.add_parser("eval-status")
    eval_status_parser.add_argument("--run", required=True)
    eval_verify_parser = subparsers.add_parser("eval-verify")
    eval_verify_parser.add_argument("--run", required=True)
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


def _run_eval_command(args: argparse.Namespace) -> int:
    try:
        run = Path(args.run)
        if args.command == "eval-init":
            case_path = Path(args.case)
            case, capsule_paths = _case_and_capsules_from_fixture(
                case_path, root=case_path.parent
            )
            state = initialize_evaluation(
                case,
                run,
                seed_hex=args.seed_hex,
                generation_capsule_paths=capsule_paths,
            )
            _eval_json(_state_payload(state))
            return EVAL_EXIT_SUCCESS
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
