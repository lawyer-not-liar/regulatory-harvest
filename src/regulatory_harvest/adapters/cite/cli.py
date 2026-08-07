"""Lazy command-line entry points for cite exchange operations."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from regulatory_harvest.models import ResearchBundle
from regulatory_harvest.storage import FileSystemArtifactStore, canonical_json_bytes

from .client import CiteClient, CiteCompatibilityError, CiteRequestError
from .exporter import (
    CiteDocumentTarget,
    CiteExportResult,
    CiteExportValidationError,
    export_bundle_to_cite,
)
from .importer import CiteImportResult, import_cite_corpus

EXIT_SUCCESS = 0
EXIT_INPUT = 2
EXIT_INCOMPLETE = 3
EXIT_INVALID_BUNDLE = 4


class CiteCliInputError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _json_line(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def _token(args: argparse.Namespace, *, required: bool) -> str | None:
    token = os.environ.get(args.token_env)
    if required and not token:
        raise CiteCliInputError(
            "cite_token_missing",
            f"environment variable {args.token_env!r} is not set",
        )
    return token or None


async def _write_receipt(
    output: Path,
    filename: str,
    result: CiteImportResult | CiteExportResult,
) -> Path:
    if output.name in {"", ".", ".."}:
        raise CiteCliInputError("cite_output_invalid", "output must name a directory")
    store = FileSystemArtifactStore(output.parent)
    await store.write_atomic(
        output.name,
        filename,
        canonical_json_bytes(result) + b"\n",
    )
    return output / filename


async def _run_import(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    token = _token(args, required=args.require_auth)
    async with CiteClient(args.url, token=token) as client:
        result = await import_cite_corpus(client, args.corpus)
        receipt = await _write_receipt(args.output, "cite-import.json", result)
        incomplete = bool(result.gaps)
        return (
            EXIT_INCOMPLETE if incomplete else EXIT_SUCCESS,
            {
                "corpus": result.corpus_id,
                "gaps": len(result.gaps),
                "ok": not incomplete,
                "receipt": str(receipt),
                "target": client.base_url,
            },
        )


def _load_bundle(path: Path) -> ResearchBundle:
    return ResearchBundle.model_validate_json(path.read_text(encoding="utf-8"))


def _load_targets(path: Path) -> dict[str, CiteDocumentTarget]:
    adapter = TypeAdapter(dict[str, CiteDocumentTarget])
    return adapter.validate_json(path.read_text(encoding="utf-8"))


def _load_previous(path: Path | None) -> CiteExportResult | None:
    if path is None:
        return None
    return CiteExportResult.model_validate_json(path.read_text(encoding="utf-8"))


async def _run_export(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    token = _token(args, required=True)
    bundle = _load_bundle(args.bundle)
    targets = _load_targets(args.document_targets)
    previous = _load_previous(args.previous_receipt)
    async with CiteClient(args.url, token=token) as client:
        result = await export_bundle_to_cite(
            client,
            args.corpus,
            bundle,
            annotation_label_id=args.annotation_label_id,
            relationship_label_id=args.relationship_label_id,
            document_targets=targets,
            previous_result=previous,
            concurrency=args.concurrency,
        )
        receipt = await _write_receipt(args.output, "cite-export.json", result)
        incomplete = any(entry.status in {"failed", "skipped"} for entry in result.entries)
        return (
            EXIT_INCOMPLETE if incomplete else EXIT_SUCCESS,
            {
                "corpus": result.corpus_id,
                "entries": len(result.entries),
                "ok": not incomplete,
                "receipt": str(receipt),
                "target": client.base_url,
            },
        )


def run_cite_command(args: argparse.Namespace) -> int:
    """Run one cite subcommand and render a stable, sanitized status."""
    try:
        operation = _run_import(args) if args.cite_command == "import" else _run_export(args)
        exit_code, payload = asyncio.run(operation)
        if args.json_output:
            _json_line(payload)
        elif exit_code == EXIT_SUCCESS:
            print(f"Wrote {payload['receipt']}")
        else:
            print(f"cite exchange incomplete; receipt: {payload['receipt']}", file=sys.stderr)
        return exit_code
    except CiteExportValidationError as error:
        if args.json_output:
            _json_line({"error": "cite_bundle_invalid", "ok": False})
        else:
            print(f"Bundle is not exportable: {error}", file=sys.stderr)
        return EXIT_INVALID_BUNDLE
    except CiteCompatibilityError:
        if args.json_output:
            _json_line({"error": "cite_incompatible", "ok": False})
        else:
            print("cite target is missing a required operation", file=sys.stderr)
        return EXIT_INCOMPLETE
    except CiteRequestError:
        if args.json_output:
            _json_line({"error": "cite_request_failed", "ok": False})
        else:
            print("cite request failed; remote details were suppressed", file=sys.stderr)
        return EXIT_INCOMPLETE
    except CiteCliInputError as error:
        if args.json_output:
            _json_line({"error": error.code, "ok": False})
        else:
            print(f"Invalid cite configuration: {error}", file=sys.stderr)
        return EXIT_INPUT
    except (OSError, ValidationError, ValueError) as error:
        if args.json_output:
            _json_line({"error": "cite_input_invalid", "ok": False})
        else:
            print(f"Invalid cite input: {error}", file=sys.stderr)
        return EXIT_INPUT
