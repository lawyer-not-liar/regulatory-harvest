"""Command-line interface for local Regulatory Harvest projects."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from regulatory_harvest.api import (
    render_audit,
    render_report,
    run_research_sync,
    validate_research_bundle,
)
from regulatory_harvest.combine import CombineError, StageExecutionError
from regulatory_harvest.models import ResearchRequest, SourceInput, StageName

EXIT_SUCCESS = 0
EXIT_INPUT = 2
EXIT_INCOMPLETE = 3
EXIT_INVALID_BUNDLE = 4


def _json_line(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", dest="json_output")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harvest")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create a request template")
    init_parser.add_argument("directory", type=Path)
    init_parser.add_argument("--force", action="store_true")
    _add_json_flag(init_parser)

    run_parser = subparsers.add_parser("run", help="run the COMBINE pipeline")
    run_parser.add_argument("--request", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--force-stage", choices=[stage.value for stage in StageName])
    run_parser.add_argument("--clear-stale-lock", action="store_true")
    _add_json_flag(run_parser)

    validate_parser = subparsers.add_parser("validate", help="validate a bundle")
    validate_parser.add_argument("bundle", type=Path)
    _add_json_flag(validate_parser)

    report_parser = subparsers.add_parser("report", help="render a bundle as Markdown")
    report_parser.add_argument("bundle", type=Path)
    report_parser.add_argument("--output", type=Path)
    report_parser.add_argument("--audit-output", type=Path)
    _add_json_flag(report_parser)

    cite_parser = subparsers.add_parser("cite", help="exchange records with cite")
    cite_subparsers = cite_parser.add_subparsers(dest="cite_command", required=True)

    cite_import = cite_subparsers.add_parser("import", help="import a cite corpus")
    cite_import.add_argument("--url", required=True)
    cite_import.add_argument("--corpus", required=True)
    cite_import.add_argument("--output", type=Path, required=True)
    cite_import.add_argument("--token-env", default="CITE_TOKEN")
    cite_import.add_argument("--require-auth", action="store_true")
    _add_json_flag(cite_import)

    cite_export = cite_subparsers.add_parser("export", help="export a Harvest bundle")
    cite_export.add_argument("--url", required=True)
    cite_export.add_argument("--corpus", required=True)
    cite_export.add_argument("--bundle", type=Path, required=True)
    cite_export.add_argument("--document-targets", type=Path, required=True)
    cite_export.add_argument("--annotation-label-id", required=True)
    cite_export.add_argument("--relationship-label-id")
    cite_export.add_argument("--previous-receipt", type=Path)
    cite_export.add_argument("--output", type=Path, required=True)
    cite_export.add_argument("--token-env", default="CITE_TOKEN")
    cite_export.add_argument("--concurrency", type=int, default=1)
    _add_json_flag(cite_export)

    eval_parser = subparsers.add_parser("eval", help="evaluate retrieval outputs")
    eval_subparsers = eval_parser.add_subparsers(dest="eval_command", required=True)
    legalbench = eval_subparsers.add_parser(
        "legalbench-rag",
        help="evaluate a user-supplied LegalBench-RAG dataset",
        description="Evaluate predictions against a user-supplied LegalBench-RAG dataset.",
    )
    legalbench.add_argument("--dataset", type=Path, required=True)
    legalbench.add_argument("--predictions", type=Path, required=True)
    legalbench.add_argument("--output", type=Path, required=True)
    legalbench.add_argument("--config-file", type=Path)
    legalbench.add_argument("--accept-upstream-terms", action="store_true")
    _add_json_flag(legalbench)
    attorney = eval_subparsers.add_parser(
        "attorney", help="run local scripted attorney-evaluation fixtures only"
    )
    attorney_subparsers = attorney.add_subparsers(dest="attorney_command", required=True)
    attorney_run = attorney_subparsers.add_parser("run", help="run a local scripted fixture")
    attorney_run.add_argument("--case", type=Path, required=True)
    attorney_run.add_argument("--scripted-responses", type=Path)
    attorney_run.add_argument("--output", type=Path, required=True)
    _add_json_flag(attorney_run)
    attorney_verify = attorney_subparsers.add_parser("verify", help="read-only run verification")
    attorney_verify.add_argument("--output", type=Path, required=True)
    _add_json_flag(attorney_verify)
    return parser


def _init(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    path = directory / "request.json"
    if path.exists() and not args.force:
        if args.json_output:
            _json_line({"error": "request_exists", "ok": False})
        else:
            print(f"Request already exists: {path}", file=sys.stderr)
        return EXIT_INPUT
    directory.mkdir(parents=True, exist_ok=True)
    request = ResearchRequest(
        request_id="research-run",
        question="What regulatory requirements apply?",
        jurisdictions=["US"],
        as_of=date.today(),
        source_inputs=[SourceInput(location="example-rule.txt")],
    )
    path.write_text(request.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if args.json_output:
        _json_line({"created": str(path), "ok": True})
    else:
        print(f"Created {path}")
    return EXIT_SUCCESS


def _run(args: argparse.Namespace) -> int:
    force_stage = StageName(args.force_stage) if args.force_stage is not None else None
    result = run_research_sync(
        args.request,
        args.output,
        force_stage=force_stage,
        clear_stale_lock=args.clear_stale_lock,
    )
    bundle_path = args.output / result.manifest.run_id / "bundle.json"
    validation_valid = (
        result.bundle.validation.valid if result.bundle.validation is not None else False
    )
    payload = {
        "bundle": str(bundle_path),
        "ok": True,
        "run_id": result.manifest.run_id,
        "validation_valid": validation_valid,
    }
    if args.json_output:
        _json_line(payload)
    else:
        print(f"Completed run {result.manifest.run_id}: {bundle_path}")
    return EXIT_SUCCESS if validation_valid else EXIT_INVALID_BUNDLE


def _validate(args: argparse.Namespace) -> int:
    report = validate_research_bundle(args.bundle)
    payload = report.model_dump(mode="json")
    if args.json_output:
        _json_line(payload)
    else:
        print("Bundle is valid." if report.valid else "Bundle is invalid.")
        for issue in report.issues:
            print(f"{issue.level.value}: {issue.code}: {issue.message}", file=sys.stderr)
    return EXIT_SUCCESS if report.valid else EXIT_INVALID_BUNDLE


def _report(args: argparse.Namespace) -> int:
    validation = validate_research_bundle(args.bundle)
    report = render_report(args.bundle)
    audit = render_audit(args.bundle)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    if args.audit_output is not None:
        args.audit_output.parent.mkdir(parents=True, exist_ok=True)
        args.audit_output.write_text(audit, encoding="utf-8")
    if args.json_output:
        payload: dict[str, Any] = {
            "audit": audit,
            "ok": validation.valid,
            "report": report,
        }
        if args.output is not None:
            payload["output"] = str(args.output)
        if args.audit_output is not None:
            payload["audit_output"] = str(args.audit_output)
        _json_line(payload)
    elif args.output is None:
        print(report)
    else:
        print(f"Wrote {args.output}")
    return EXIT_SUCCESS if validation.valid else EXIT_INVALID_BUNDLE


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "cite":
            from regulatory_harvest.adapters.cite.cli import run_cite_command

            return run_cite_command(args)
        if args.command == "eval":
            from regulatory_harvest.evaluation.cli import run_evaluation_command

            return run_evaluation_command(args)
        if args.command == "init":
            return _init(args)
        if args.command == "run":
            return _run(args)
        if args.command == "validate":
            return _validate(args)
        return _report(args)
    except StageExecutionError as error:
        if args.json_output:
            _json_line({"error": "stage_failed", "ok": False, "stage": error.stage.value})
        else:
            print(str(error), file=sys.stderr)
        return EXIT_INCOMPLETE
    except (OSError, ValidationError, ValueError, CombineError) as error:
        if args.json_output:
            _json_line({"error": type(error).__name__, "ok": False})
        else:
            print(f"Invalid input or configuration: {error}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
