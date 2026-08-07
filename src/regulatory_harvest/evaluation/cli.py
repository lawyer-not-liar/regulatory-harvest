"""Lazy CLI wrapper for user-supplied evaluation datasets."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from pydantic import TypeAdapter, ValidationError

from .runner import (
    ConfigurationValue,
    UpstreamTermsNotAcceptedError,
    run_legalbench_evaluation,
)


def _json_line(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def _configuration(args: argparse.Namespace) -> dict[str, ConfigurationValue]:
    if args.config_file is None:
        return {}
    adapter = TypeAdapter(dict[str, ConfigurationValue])
    return adapter.validate_json(args.config_file.read_text(encoding="utf-8"))


def run_evaluation_command(args: argparse.Namespace) -> int:
    """Run LegalBench-RAG evaluation with stable CLI exit semantics."""
    try:
        result = run_legalbench_evaluation(
            args.dataset,
            args.predictions,
            args.output,
            accept_upstream_terms=args.accept_upstream_terms,
            retrieval_configuration=_configuration(args),
        )
        payload = {
            "cases": len(result.summary.cases),
            "macro_f1": result.summary.macro_f1,
            "micro_f1": result.summary.micro_f1,
            "ok": True,
            "output": str(args.output),
        }
        if args.json_output:
            _json_line(payload)
        else:
            print(f"Wrote {args.output}")
        return 0
    except UpstreamTermsNotAcceptedError:
        if args.json_output:
            _json_line({"error": "upstream_terms_not_accepted", "ok": False})
        else:
            print("Upstream dataset terms were not acknowledged.", file=sys.stderr)
        return 2
    except (OSError, ValidationError, ValueError) as error:
        if args.json_output:
            _json_line({"error": "evaluation_input_invalid", "ok": False})
        else:
            print(f"Invalid evaluation input: {error}", file=sys.stderr)
        return 2
