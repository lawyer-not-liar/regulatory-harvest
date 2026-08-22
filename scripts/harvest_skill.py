#!/usr/bin/env python3
"""Bridge a host agent's research charter and analysis draft into COMBINE."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from datetime import date
from pathlib import Path, PureWindowsPath
from typing import Any, Literal, Never, cast
from urllib.parse import urlsplit

SKILL_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = SKILL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from regulatory_harvest.runtime import runtime_available  # noqa: E402


def _unsafe_managed_path(matter: Path, relative_paths: tuple[Path, ...]) -> Path | None:
    for relative_path in relative_paths:
        candidate = matter / relative_path
        if candidate.is_symlink():
            return candidate
        if not candidate.exists():
            continue
        if not candidate.is_dir():
            return candidate
        try:
            candidate.resolve(strict=True).relative_to(matter)
        except (OSError, ValueError):
            return candidate
    return None


def _write_error(code: str, message: str) -> None:
    sys.stderr.write(json.dumps({"code": code, "message": message}, sort_keys=True) + "\n")


def _full_evaluation_runner() -> Any:
    evaluation_path = Path(__file__).with_name("attorney_eval_full.py")
    evaluation_spec = importlib.util.spec_from_file_location(
        "regulatory_harvest_attorney_eval_full", evaluation_path
    )
    if evaluation_spec is None or evaluation_spec.loader is None:
        raise RuntimeError("the full evaluation runner is unavailable")
    evaluation_module = importlib.util.module_from_spec(evaluation_spec)
    evaluation_spec.loader.exec_module(evaluation_module)
    return evaluation_module


# Evaluation, including recoverable full-runtime resume, has a deliberately
# narrower dependency surface than research. Dispatch it before probing or
# importing the research/briefing stack so a clean evaluation installation
# cannot be broken by unrelated optional models.
_IS_EVALUATION_COMMAND = (
    __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1].startswith("eval-")
)
if _IS_EVALUATION_COMMAND and importlib.util.find_spec("pydantic") is not None:
    try:
        evaluation_module = _full_evaluation_runner()
    except RuntimeError:
        _write_error("RUNTIME_UNAVAILABLE", "The full evaluation runner is unavailable.")
        raise SystemExit(5) from None
    raise SystemExit(evaluation_module.main(sys.argv[1:]))


if not runtime_available():
    portable_path = Path(__file__).with_name("harvest_portable.py")
    portable_spec = importlib.util.spec_from_file_location(
        "regulatory_harvest_portable", portable_path
    )
    if portable_spec is None or portable_spec.loader is None:
        _write_error("RUNTIME_UNAVAILABLE", "The portable deterministic runner is unavailable.")
        raise SystemExit(5)
    portable_module = importlib.util.module_from_spec(portable_spec)
    portable_spec.loader.exec_module(portable_module)
    raise SystemExit(portable_module.main(sys.argv[1:]))

from pydantic import Field, ValidationError, field_validator  # noqa: E402

from regulatory_harvest.analysis import (  # noqa: E402
    ATOMIC_COVERAGE_CONTRACT_VERSION,
    AnalysisDraft,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_atomic_coverage,
    evaluate_coverage_closure,
    evaluate_provision_recall,
)
from regulatory_harvest.analysis.proposition_coverage import (  # noqa: E402
    COVERAGE_CONTRACT_VERSION,
)
from regulatory_harvest.api import run_research_sync, validate_research_bundle  # noqa: E402
from regulatory_harvest.models import (  # noqa: E402
    ClaimKind,
    ResearchRequest,
    SourceInput,
    SourceRecord,
    StageName,
)
from regulatory_harvest.models.base import StrictModel  # noqa: E402
from regulatory_harvest.providers import AgentDraftModelProvider  # noqa: E402
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest  # noqa: E402

PROPOSITION_COVERAGE_V1 = COVERAGE_CONTRACT_VERSION
PROPOSITION_COVERAGE_V2 = ATOMIC_COVERAGE_CONTRACT_VERSION


class SkillInputError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ResearchCharter(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    matter_id: str
    matter_title: str
    question: str
    jurisdictions: list[str] = Field(min_length=1)
    as_of: date
    source_mode: Literal["provided-only", "web"]
    sources: list[SourceInput] = Field(min_length=1)
    context: str | None = None
    excluded_topics: list[str] = Field(default_factory=list)
    output_instructions: str | None = None

    @field_validator("matter_title")
    @classmethod
    def validate_matter_title(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped

    @field_validator("matter_id")
    @classmethod
    def validate_matter_id(cls, value: str) -> str:
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if (
            not value
            or value in {".", ".."}
            or len(value) > 80
            or value[0] not in allowed - {".", "-", "_"}
            or any(character not in allowed for character in value)
        ):
            raise ValueError("must be one safe path component of at most 80 characters")
        return value


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise SkillInputError("INVALID_ARGUMENTS", message)


def _validation_message(error: ValidationError) -> str:
    messages: list[str] = []
    for item in error.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        messages.append(f"{location}: {item['msg']}")
    return "; ".join(messages)


def _read_charter(path: Path) -> ResearchCharter:
    try:
        return ResearchCharter.model_validate_json(path.read_bytes())
    except ValidationError as error:
        raise SkillInputError("INVALID_CHARTER", _validation_message(error)) from None
    except (OSError, ValueError):
        raise SkillInputError("INVALID_CHARTER", "The charter could not be read as JSON.") from None


def _read_draft(path: Path) -> AnalysisDraft:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SkillInputError(
            "INVALID_DRAFT", "The analysis draft could not be read as JSON."
        ) from None
    try:
        return AnalysisDraft.model_validate(payload)
    except ValidationError as error:
        if isinstance(payload, dict) and "coverage_contract_version" in payload:
            raw_contract = payload.get("coverage_contract_version")
            if raw_contract == PROPOSITION_COVERAGE_V2 and (
                payload.get("lead_reviews") or payload.get("proposition_coverage")
            ):
                reparsed_payload = dict(payload)
                reparsed_payload["coverage_contract_version"] = PROPOSITION_COVERAGE_V1
                try:
                    parsed = AnalysisDraft.model_validate(reparsed_payload)
                except ValidationError:
                    pass
                else:
                    return parsed.model_copy(
                        update={"coverage_contract_version": PROPOSITION_COVERAGE_V2}
                    )
            if (
                raw_contract is not None
                and raw_contract != PROPOSITION_COVERAGE_V1
                and raw_contract != PROPOSITION_COVERAGE_V2
            ):
                reparsed_payload = dict(payload)
                reparsed_payload["coverage_contract_version"] = None
                try:
                    parsed = AnalysisDraft.model_validate(reparsed_payload)
                except ValidationError:
                    pass
                else:
                    return parsed.model_copy(
                        update={"coverage_contract_version": raw_contract}
                    )
        raise SkillInputError("INVALID_DRAFT", _validation_message(error)) from None


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json_bytes(value) + b"\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _copy_atomic(source: Path, target: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as source_stream, os.fdopen(descriptor, "wb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _matter_path(value: str, *, must_exist: bool = False) -> Path:
    path = Path(value).expanduser().resolve(strict=False)
    if path.exists() and not path.is_dir():
        raise SkillInputError("INVALID_MATTER", "The selected matter path is not a directory.")
    if must_exist and not path.is_dir():
        raise SkillInputError("INVALID_MATTER", "The selected matter directory does not exist.")
    return path


def _validate_matter_layout(matter: Path, *, run_id: str | None = None) -> None:
    managed = [
        Path("inputs"),
        Path("runs"),
        Path(".regulatory-harvest"),
        Path(".regulatory-harvest/runtime"),
    ]
    if run_id is not None:
        managed.append(Path("runs") / run_id)
    if _unsafe_managed_path(matter, tuple(managed)) is not None:
        raise SkillInputError(
            "INVALID_MATTER",
            "A managed matter path is a symlink, non-directory, or escapes the matter.",
        )


def _stage_local_sources(
    charter: ResearchCharter,
    *,
    charter_dir: Path,
    matter: Path,
) -> list[SourceInput]:
    staged: list[SourceInput] = []
    inputs = matter / "inputs"
    for index, source in enumerate(charter.sources, start=1):
        location = source.location
        windows_absolute = PureWindowsPath(location).is_absolute()
        parsed = urlsplit(location)
        if not windows_absolute and parsed.scheme in {"http", "https"}:
            staged.append(source)
            continue
        if not windows_absolute and parsed.scheme:
            raise SkillInputError(
                "INVALID_SOURCE",
                "Source locations must be local files or public HTTP(S) URLs.",
            )
        source_path = Path(location).expanduser()
        if not source_path.is_absolute():
            source_path = charter_dir / source_path
        try:
            source_path = source_path.resolve(strict=True)
        except OSError:
            raise SkillInputError(
                "SOURCE_NOT_FOUND", f"A local source was not found: {Path(source.location).name}"
            ) from None
        if not source_path.is_file():
            raise SkillInputError(
                "INVALID_SOURCE", f"A local source is not a regular file: {source_path.name}"
            )
        suffix = source_path.suffix.lower()
        target = inputs / f"{index:03d}-{source_path.stem[:60]}{suffix}"
        inputs.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise SkillInputError(
                "INVALID_MATTER", "A managed input path must not be a symbolic link."
            )
        _copy_atomic(source_path, target)
        staged.append(source.model_copy(update={"location": target.relative_to(matter).as_posix()}))
    return staged


def prepare(charter_path: Path, matter: Path) -> dict[str, object]:
    charter_path = charter_path.expanduser().resolve(strict=True)
    charter = _read_charter(charter_path)
    matter.mkdir(parents=True, exist_ok=True)
    _validate_matter_layout(matter, run_id=charter.matter_id)
    request_path = matter / "request.json"
    staged_sources = _stage_local_sources(
        charter,
        charter_dir=charter_path.parent,
        matter=matter,
    )
    request = ResearchRequest(
        request_id=charter.matter_id,
        question=charter.question,
        matter_title=charter.matter_title,
        jurisdictions=charter.jurisdictions,
        as_of=charter.as_of,
        source_mode=charter.source_mode,
        source_inputs=staged_sources,
        context=charter.context,
        excluded_topics=charter.excluded_topics,
        output_instructions=charter.output_instructions,
    )
    _write_json(matter / "research-charter.json", charter)
    _write_json(request_path, request)
    result = run_research_sync(
        request_path,
        matter / "runs",
        force_stage=StageName.COLLECT,
    )
    succeeded = sum(source.fetch_status.value == "succeeded" for source in result.bundle.sources)
    failed = len(result.bundle.sources) - succeeded
    evidence_inventory = build_evidence_inventory(
        [source.model_dump(mode="json") for source in result.bundle.sources]
    )
    source_unit_inventory = build_source_unit_inventory(
        [source.model_dump(mode="json") for source in result.bundle.sources]
    )
    dossier = {
        "schema_version": "1.0",
        "coverage_contract_version": PROPOSITION_COVERAGE_V2,
        "source_mode": charter.source_mode,
        "request": request,
        "sources": result.bundle.sources,
        "gaps": result.bundle.gaps,
        "evidence_inventory": evidence_inventory,
        "source_unit_inventory": source_unit_inventory,
    }
    dossier_path = matter / "agent-dossier.json"
    _write_json(dossier_path, dossier)
    if succeeded == 0:
        raise SkillInputError(
            "NO_USABLE_SOURCES",
            "No source was retrieved successfully; inspect the dossier and revise the source set.",
        )
    return {
        "dossier": str(dossier_path),
        "matter": str(matter),
        "request": str(request_path),
        "source_counts": {"failed": failed, "succeeded": succeeded},
        "evidence_lead_counts": evidence_inventory["topic_counts"],
        "priority_evidence_lead_counts": evidence_inventory[
            "priority_topic_counts"
        ],
        "source_unit_count": source_unit_inventory["unit_count"],
        "status": "prepared",
    }


def finalize(
    matter: Path,
    draft_path: Path,
    *,
    host_name: str,
    model_name: str,
) -> tuple[dict[str, object], int]:
    _validate_matter_layout(matter)
    request_path = matter / "request.json"
    if not request_path.is_file():
        raise SkillInputError(
            "MATTER_NOT_PREPARED", "Run the prepare command before finalizing analysis."
        )
    dossier_path = matter / "agent-dossier.json"
    try:
        dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
        if not isinstance(dossier, dict) or not isinstance(dossier.get("sources"), list):
            raise ValueError
        prepared_sources = [
            SourceRecord.model_validate(source) for source in dossier["sources"]
        ]
        raw_inventory = dossier.get("evidence_inventory", {"leads": []})
        if not isinstance(raw_inventory, dict):
            raise ValueError
    except (OSError, ValueError, ValidationError):
        raise SkillInputError(
            "INVALID_DOSSIER", "The prepared source inventory is invalid."
        ) from None
    contract_version = dossier.get("coverage_contract_version")
    has_contract = "coverage_contract_version" in dossier
    has_units = "source_unit_inventory" in dossier
    if contract_version in (PROPOSITION_COVERAGE_V1, PROPOSITION_COVERAGE_V2):
        raw_units = dossier.get("source_unit_inventory")
        if not isinstance(raw_units, dict):
            raise SkillInputError(
                "INVALID_DOSSIER", "The prepared source-unit inventory is invalid."
            )
    elif not has_contract and not has_units:
        raw_units = None
    else:
        raise SkillInputError(
            "INVALID_DOSSIER", "The prepared coverage contract is invalid."
        )

    draft = _read_draft(draft_path.expanduser().resolve(strict=True))
    if not draft.findings:
        raise SkillInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must contain at least one substantive finding.",
        )
    has_supported_evidence = any(
        claim.kind is ClaimKind.SOURCE_SUPPORTED and claim.proposed_citations
        for finding in draft.findings
        for claim in finding.claims
    )
    if not has_supported_evidence:
        raise SkillInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must contain at least one source-supported claim with evidence.",
        )
    if draft.brief is None:
        raise SkillInputError(
            "INCOMPLETE_DRAFT",
            "The analysis draft must include an authored attorney brief.",
        )
    stored_draft = matter / "analysis-draft.json"
    _write_json(stored_draft, draft)

    coverage_review: dict[str, Any]
    proposition_coverage_valid: bool | None
    if contract_version == PROPOSITION_COVERAGE_V2:
        assert isinstance(raw_units, dict)
        coverage_review = evaluate_atomic_coverage(
            raw_units,
            raw_inventory,
            draft,
            prepared_sources,
        )
        proposition_coverage_valid = coverage_review["valid"] is True
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issue_count = len(cast(list[object], coverage_review["issues"]))
    elif contract_version == PROPOSITION_COVERAGE_V1:
        assert isinstance(raw_units, dict)
        coverage_draft = draft
        if draft.coverage_contract_version != PROPOSITION_COVERAGE_V1:
            coverage_draft = draft.model_copy(
                update={"coverage_contract_version": None}
            )
        coverage_review = evaluate_coverage_closure(
            raw_inventory,
            raw_units,
            coverage_draft,
            prepared_sources,
        )
        proposition_coverage_valid = coverage_review["proposition_coverage"]["valid"] is True
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issue_count = len(coverage_review["lead_recall"]["issues"]) + len(
            coverage_review["proposition_coverage"]["issues"]
        )
    else:
        coverage_review = evaluate_provision_recall(
            raw_inventory,
            draft,
            prepared_sources,
        )
        proposition_coverage_valid = None
        provision_recall_valid = coverage_review["valid"] is True
        coverage_issue_count = len(coverage_review["issues"])
    coverage_path = matter / "coverage-review.json"
    _write_json(coverage_path, coverage_review)
    provider_draft = draft
    if draft.coverage_contract_version == PROPOSITION_COVERAGE_V2 and (
        draft.lead_reviews or draft.proposition_coverage
    ):
        provider_draft = draft.model_copy(
            update={"lead_reviews": [], "proposition_coverage": []}
        )
    resolved_host = host_name.strip() or "host-agent"
    resolved_model = model_name.strip() or "host-configured-model"
    fingerprint = "agent-draft-v2:" + sha256_digest(
        canonical_json_bytes(
            {
                "bridge_version": "agent-draft-v2",
                "draft": provider_draft,
                "host_name": resolved_host,
                "model_name": resolved_model,
            }
        )
    )
    provider = AgentDraftModelProvider(
        provider_draft,
        host_name=resolved_host,
        model_name=resolved_model,
    )
    result = run_research_sync(
        request_path,
        matter / "runs",
        model_provider=provider,
        model_provider_fingerprint=fingerprint,
    )
    bundle_path = matter / "runs" / result.manifest.run_id / "bundle.json"
    report_path = matter / "runs" / result.manifest.run_id / "report.md"
    audit_path = matter / "runs" / result.manifest.run_id / "audit.md"
    validation = validate_research_bundle(bundle_path)
    blocking_review_codes = {
        "PROPOSED_QUOTE_AMBIGUOUS",
        "PROPOSED_QUOTE_NOT_FOUND",
        "PROPOSED_SOURCE_MISSING",
    }
    blocking_review_count = sum(
        item.code in blocking_review_codes for item in result.bundle.review_items
    )
    evidence_precision_valid = validation.valid and blocking_review_count == 0
    completed = evidence_precision_valid and provision_recall_valid
    receipt = {
        "analysis_draft": str(stored_draft),
        "audit": str(audit_path),
        "blocking_review_count": blocking_review_count,
        "bundle": str(bundle_path),
        "coverage_issue_count": coverage_issue_count,
        "coverage_review": str(coverage_path),
        "coverage_review_hash": coverage_review["coverage_review_hash"],
        "evidence_precision_valid": evidence_precision_valid,
        "proposition_coverage_valid": proposition_coverage_valid,
        "provision_recall_valid": provision_recall_valid,
        "report": str(report_path),
        "status": "completed" if completed else "review-required",
        "valid": validation.valid,
        "validation_issue_count": len(validation.issues),
    }
    _write_json(matter / "validation-receipt.json", receipt)
    return receipt, 0 if completed else 4


def _parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(prog="harvest-skill")
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=JsonArgumentParser
    )
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--charter", required=True)
    prepare_parser.add_argument("--matter", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--matter", required=True)
    finalize_parser.add_argument("--draft", required=True)
    finalize_parser.add_argument("--host", default="host-agent")
    finalize_parser.add_argument("--model", default="host-configured-model")
    return parser


def _safe_evaluation_verification_issues(issues: tuple[str, ...]) -> list[str]:
    """Compatibility wrapper for existing in-process runner consumers."""
    return cast(
        list[str],
        _full_evaluation_runner()._safe_evaluation_verification_issues(issues),
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0].startswith("eval-"):
        return cast(int, _full_evaluation_runner().main(arguments))
    try:
        args = _parser().parse_args(arguments)
        if args.command == "prepare":
            matter = _matter_path(args.matter)
            receipt = prepare(Path(args.charter), matter)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        matter = _matter_path(args.matter, must_exist=True)
        receipt, status = finalize(
            matter,
            Path(args.draft),
            host_name=args.host,
            model_name=args.model,
        )
        print(json.dumps(receipt, sort_keys=True))
        return status
    except SkillInputError as error:
        _write_error(error.code, str(error))
        return 2
    except FileNotFoundError:
        _write_error("INPUT_NOT_FOUND", "A required input file was not found.")
        return 2
    except Exception as error:
        _write_error(
            "ENGINE_FAILURE",
            f"The deterministic engine could not complete ({type(error).__name__}).",
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
