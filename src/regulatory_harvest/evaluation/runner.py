"""Text-free LegalBench-RAG evaluation runner and result artifacts."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Protocol

from pydantic import Field

from regulatory_harvest import __version__
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .legalbench_rag import (
    EvaluationSummary,
    LegalBenchCase,
    LegalBenchDataset,
    RetrievedSpan,
    evaluate_spans,
    load_legalbench_dataset,
    validate_prediction_spans,
)

ConfigurationValue = str | int | float | bool | None


class Retriever(Protocol):
    async def retrieve(self, case: LegalBenchCase) -> list[RetrievedSpan]: ...


class UpstreamTermsNotAcceptedError(ValueError):
    """A non-synthetic dataset was supplied without explicit terms acknowledgement."""


class PredictionRecord(StrictModel):
    case_id: str
    spans: list[RetrievedSpan] = Field(default_factory=list)


class DatasetFileFingerprint(StrictModel):
    relative_path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LegalBenchEvaluationResult(StrictModel):
    benchmark: str = "LegalBench-RAG"
    package_version: str
    synthetic_fixture: bool
    upstream_terms_acknowledged: bool
    retrieval_configuration: dict[str, ConfigurationValue]
    dataset_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_files: list[DatasetFileFingerprint]
    predictions_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary: EvaluationSummary
    scope_limitation: str = (
        "Measures exact-character retrieval on the supplied LegalBench-RAG dataset; "
        "it does not measure end-to-end regulatory research correctness."
    )


def _load_predictions(path: Path) -> dict[str, list[RetrievedSpan]]:
    predictions: dict[str, list[RetrievedSpan]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("predictions file is not UTF-8") from error
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = PredictionRecord.model_validate_json(line)
        except ValueError as error:
            raise ValueError(f"invalid prediction record on line {line_number}") from error
        if record.case_id in predictions:
            raise ValueError(f"duplicate prediction case_id {record.case_id!r}")
        predictions[record.case_id] = record.spans
    return predictions


def _dataset_files(dataset_root: Path) -> list[DatasetFileFingerprint]:
    root = dataset_root.expanduser().resolve(strict=True)
    fingerprints: list[DatasetFileFingerprint] = []
    for directory_name in ("benchmarks", "corpus"):
        directory = (root / directory_name).resolve(strict=True)
        if not directory.is_relative_to(root) or not directory.is_dir():
            raise ValueError(f"dataset {directory_name}/ resolves outside dataset root")
        candidates = sorted(
            (item for item in directory.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(root).as_posix(),
        )
        for candidate in candidates:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(directory):
                raise ValueError("dataset file resolves outside selected dataset root")
            data = resolved.read_bytes()
            fingerprints.append(
                DatasetFileFingerprint(
                    relative_path=resolved.relative_to(root).as_posix(),
                    size_bytes=len(data),
                    sha256=sha256_digest(data),
                )
            )
    return fingerprints


def _write_atomic(path: Path, result: LegalBenchEvaluationResult) -> None:
    if path.name in {"", ".", ".."}:
        raise ValueError("output must name a JSON file")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_json_bytes(result) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _build_result(
    dataset_path: Path,
    dataset: LegalBenchDataset,
    predictions: dict[str, list[RetrievedSpan]],
    predictions_fingerprint: str,
    *,
    accept_upstream_terms: bool,
    retrieval_configuration: dict[str, ConfigurationValue],
) -> LegalBenchEvaluationResult:
    validate_prediction_spans(dataset_path, predictions)
    summary = evaluate_spans(dataset.cases, predictions)
    dataset_files = _dataset_files(dataset_path)
    dataset_fingerprint = sha256_digest(canonical_json_bytes(dataset_files))
    return LegalBenchEvaluationResult(
        package_version=__version__,
        synthetic_fixture=dataset.synthetic,
        upstream_terms_acknowledged=accept_upstream_terms,
        retrieval_configuration=retrieval_configuration,
        dataset_fingerprint=dataset_fingerprint,
        dataset_files=dataset_files,
        predictions_fingerprint=predictions_fingerprint,
        summary=summary,
    )


def run_legalbench_evaluation(
    dataset_path: Path,
    predictions_path: Path,
    output_path: Path,
    *,
    accept_upstream_terms: bool,
    retrieval_configuration: dict[str, ConfigurationValue],
) -> LegalBenchEvaluationResult:
    """Evaluate user-provided spans and write a portable, corpus-text-free result."""
    dataset = load_legalbench_dataset(dataset_path)
    if not dataset.synthetic and not accept_upstream_terms:
        raise UpstreamTermsNotAcceptedError(
            "accept the upstream dataset terms before evaluating non-synthetic data"
        )
    predictions = _load_predictions(predictions_path)
    predictions_fingerprint = hashlib.sha256(predictions_path.read_bytes()).hexdigest()
    result = _build_result(
        dataset_path,
        dataset,
        predictions,
        predictions_fingerprint,
        accept_upstream_terms=accept_upstream_terms,
        retrieval_configuration=retrieval_configuration,
    )
    _write_atomic(output_path, result)
    return result


async def run_legalbench_retriever_evaluation(
    dataset_path: Path,
    retriever: Retriever,
    output_path: Path,
    *,
    accept_upstream_terms: bool,
    retrieval_configuration: dict[str, ConfigurationValue],
) -> LegalBenchEvaluationResult:
    """Evaluate an application-provided asynchronous retriever protocol."""
    dataset = load_legalbench_dataset(dataset_path)
    if not dataset.synthetic and not accept_upstream_terms:
        raise UpstreamTermsNotAcceptedError(
            "accept the upstream dataset terms before evaluating non-synthetic data"
        )
    predictions = {
        case.case_id: await retriever.retrieve(case)
        for case in dataset.cases
    }
    predictions_fingerprint = sha256_digest(canonical_json_bytes(predictions))
    result = _build_result(
        dataset_path,
        dataset,
        predictions,
        predictions_fingerprint,
        accept_upstream_terms=accept_upstream_terms,
        retrieval_configuration=retrieval_configuration,
    )
    _write_atomic(output_path, result)
    return result
