"""Storage-neutral reader and exact-character metrics for LegalBench-RAG."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

_KNOWN_SYNTHETIC_DATASET_FINGERPRINTS = {
    "3cffc633770647ef413cbd48ba6df57078791b0668925b4702a494fbc5a6347f"
}


class _UpstreamModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class _UpstreamSnippet(_UpstreamModel):
    file_path: str
    span: tuple[int, int]


class _UpstreamCase(_UpstreamModel):
    query: str
    snippets: list[_UpstreamSnippet]
    tags: list[str] = Field(default_factory=list)


class _UpstreamBenchmark(_UpstreamModel):
    tests: list[_UpstreamCase]


class RetrievedSpan(StrictModel):
    file_path: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    score: float | None = None

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, value: str) -> str:
        _safe_relative_path(value)
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> RetrievedSpan:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        return self


class LegalBenchCase(StrictModel):
    case_id: str
    query: str
    ground_truth: list[RetrievedSpan]
    tags: list[str] = Field(default_factory=list)


class LegalBenchDataset(StrictModel):
    cases: list[LegalBenchCase]
    corpus_files: list[str]
    benchmark_files: list[str]
    synthetic: bool = False


class CaseMetrics(StrictModel):
    truth_characters: int
    predicted_characters: int
    true_positive_characters: int
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)


class CaseEvaluation(StrictModel):
    case_id: str
    metrics: CaseMetrics


class EvaluationSummary(StrictModel):
    cases: list[CaseEvaluation]
    truth_characters: int
    predicted_characters: int
    true_positive_characters: int
    micro_precision: float = Field(ge=0.0, le=1.0)
    micro_recall: float = Field(ge=0.0, le=1.0)
    micro_f1: float = Field(ge=0.0, le=1.0)
    macro_precision: float = Field(ge=0.0, le=1.0)
    macro_recall: float = Field(ge=0.0, le=1.0)
    macro_f1: float = Field(ge=0.0, le=1.0)


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ValueError("file_path must be a safe relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and ":" in path.parts[0])
    ):
        raise ValueError("file_path must be a safe relative POSIX path")
    return path


def _directory(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"dataset requires a {name}/ directory") from error
    if not resolved.is_dir() or not resolved.is_relative_to(root):
        raise ValueError(f"dataset {name}/ must remain beneath the dataset root")
    return resolved


def _corpus_file(corpus_root: Path, relative: PurePosixPath) -> Path:
    candidate = corpus_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"corpus file {relative.as_posix()!r} is unavailable") from error
    if not resolved.is_relative_to(corpus_root):
        raise ValueError("corpus file resolves outside dataset corpus")
    if not resolved.is_file():
        raise ValueError(f"corpus path {relative.as_posix()!r} is not a file")
    return resolved


def _dataset_fingerprint(root: Path, directories: tuple[Path, ...]) -> str:
    records: list[dict[str, str | int]] = []
    for directory in directories:
        candidates = sorted(
            (item for item in directory.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(root).as_posix(),
        )
        for candidate in candidates:
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(directory):
                raise ValueError("dataset file resolves outside selected dataset root")
            data = resolved.read_bytes()
            records.append(
                {
                    "relative_path": resolved.relative_to(root).as_posix(),
                    "size_bytes": len(data),
                    "sha256": sha256_digest(data),
                }
            )
    return sha256_digest(canonical_json_bytes(records))


def load_legalbench_dataset(path: Path) -> LegalBenchDataset:
    """Load and validate a user-supplied LegalBench-RAG directory without retaining text."""
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise ValueError("dataset root does not exist") from error
    if not root.is_dir():
        raise ValueError("dataset root must be a directory")
    corpus_root = _directory(root, "corpus")
    benchmark_root = _directory(root, "benchmarks")

    benchmark_paths: list[Path] = []
    for candidate in benchmark_root.rglob("*.json"):
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(benchmark_root) or not resolved.is_file():
            raise ValueError("benchmark file resolves outside dataset benchmarks")
        benchmark_paths.append(resolved)
    benchmark_paths.sort(key=lambda item: item.relative_to(benchmark_root).as_posix())
    if not benchmark_paths:
        raise ValueError("dataset benchmarks/ contains no JSON benchmark files")

    cases: list[LegalBenchCase] = []
    corpus_lengths: dict[str, int] = {}
    for benchmark_path in benchmark_paths:
        relative_benchmark = benchmark_path.relative_to(benchmark_root).as_posix()
        try:
            benchmark = _UpstreamBenchmark.model_validate_json(
                benchmark_path.read_text(encoding="utf-8")
            )
        except UnicodeDecodeError as error:
            raise ValueError(f"benchmark {relative_benchmark!r} is not UTF-8") from error
        for index, upstream_case in enumerate(benchmark.tests):
            if not upstream_case.query.strip():
                raise ValueError(f"benchmark {relative_benchmark!r} has a blank query")
            truth: list[RetrievedSpan] = []
            for snippet in upstream_case.snippets:
                relative = _safe_relative_path(snippet.file_path)
                file_key = relative.as_posix()
                corpus_path = _corpus_file(corpus_root, relative)
                if file_key not in corpus_lengths:
                    try:
                        corpus_lengths[file_key] = len(
                            corpus_path.read_text(encoding="utf-8")
                        )
                    except UnicodeDecodeError as error:
                        raise ValueError(f"corpus file {file_key!r} is not UTF-8") from error
                start, end = snippet.span
                if start < 0 or end <= start or end > corpus_lengths[file_key]:
                    raise ValueError(
                        f"span {snippet.span!r} falls outside corpus text {file_key!r}"
                    )
                truth.append(
                    RetrievedSpan(
                        file_path=file_key,
                        start_char=start,
                        end_char=end,
                    )
                )
            cases.append(
                LegalBenchCase(
                    case_id=f"{relative_benchmark}:{index}",
                    query=upstream_case.query,
                    ground_truth=truth,
                    tags=upstream_case.tags,
                )
            )

    marker = root / "FIXTURE_LICENSE.md"
    dataset_fingerprint = _dataset_fingerprint(
        root, (benchmark_root, corpus_root)
    )
    synthetic = (
        marker.is_file()
        and "Fixture-Type: synthetic" in marker.read_text(encoding="utf-8")
        and dataset_fingerprint in _KNOWN_SYNTHETIC_DATASET_FINGERPRINTS
    )
    return LegalBenchDataset(
        cases=cases,
        corpus_files=sorted(corpus_lengths),
        benchmark_files=[
            item.relative_to(benchmark_root).as_posix() for item in benchmark_paths
        ],
        synthetic=synthetic,
    )


def validate_prediction_spans(
    dataset_path: Path,
    predictions: dict[str, list[RetrievedSpan]],
) -> None:
    """Validate predicted character ranges against user-supplied UTF-8 corpus files."""
    root = dataset_path.expanduser().resolve(strict=True)
    corpus_root = _directory(root, "corpus")
    corpus_lengths: dict[str, int] = {}
    for spans in predictions.values():
        for span in spans:
            relative = _safe_relative_path(span.file_path)
            file_key = relative.as_posix()
            corpus_path = _corpus_file(corpus_root, relative)
            if file_key not in corpus_lengths:
                try:
                    corpus_lengths[file_key] = len(corpus_path.read_text(encoding="utf-8"))
                except UnicodeDecodeError as error:
                    raise ValueError(f"corpus file {file_key!r} is not UTF-8") from error
            if span.end_char > corpus_lengths[file_key]:
                raise ValueError(
                    f"prediction span falls outside corpus text {file_key!r}"
                )


def _merged_by_document(spans: Iterable[RetrievedSpan]) -> dict[str, list[tuple[int, int]]]:
    grouped: dict[str, list[tuple[int, int]]] = {}
    for span in spans:
        grouped.setdefault(span.file_path, []).append((span.start_char, span.end_char))
    merged: dict[str, list[tuple[int, int]]] = {}
    for file_path, intervals in grouped.items():
        intervals.sort()
        combined: list[tuple[int, int]] = []
        for start, end in intervals:
            if combined and start <= combined[-1][1]:
                combined[-1] = (combined[-1][0], max(combined[-1][1], end))
            else:
                combined.append((start, end))
        merged[file_path] = combined
    return merged


def _length(intervals: dict[str, list[tuple[int, int]]]) -> int:
    return sum(end - start for values in intervals.values() for start, end in values)


def _intersection_length(
    truth: dict[str, list[tuple[int, int]]],
    predicted: dict[str, list[tuple[int, int]]],
) -> int:
    overlap = 0
    for file_path in truth.keys() & predicted.keys():
        truth_values = truth[file_path]
        predicted_values = predicted[file_path]
        truth_index = 0
        predicted_index = 0
        while truth_index < len(truth_values) and predicted_index < len(predicted_values):
            truth_start, truth_end = truth_values[truth_index]
            predicted_start, predicted_end = predicted_values[predicted_index]
            overlap += max(0, min(truth_end, predicted_end) - max(truth_start, predicted_start))
            if truth_end <= predicted_end:
                truth_index += 1
            else:
                predicted_index += 1
    return overlap


def _rates(truth: int, predicted: int, true_positive: int) -> tuple[float, float, float]:
    precision = true_positive / predicted if predicted else (1.0 if truth == 0 else 0.0)
    recall = true_positive / truth if truth else (1.0 if predicted == 0 else 0.0)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return precision, recall, f1


def score_case(
    truth: Iterable[RetrievedSpan],
    predicted: Iterable[RetrievedSpan],
) -> CaseMetrics:
    """Score unioned exact-character intervals for one query."""
    merged_truth = _merged_by_document(truth)
    merged_predicted = _merged_by_document(predicted)
    truth_characters = _length(merged_truth)
    predicted_characters = _length(merged_predicted)
    true_positive_characters = _intersection_length(merged_truth, merged_predicted)
    precision, recall, f1 = _rates(
        truth_characters,
        predicted_characters,
        true_positive_characters,
    )
    return CaseMetrics(
        truth_characters=truth_characters,
        predicted_characters=predicted_characters,
        true_positive_characters=true_positive_characters,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def evaluate_spans(
    cases: list[LegalBenchCase],
    predictions: dict[str, list[RetrievedSpan]],
) -> EvaluationSummary:
    """Calculate per-case, micro, and macro character metrics."""
    known_ids = {case.case_id for case in cases}
    unknown_ids = sorted(predictions.keys() - known_ids)
    if unknown_ids:
        raise ValueError(f"predictions contain unknown case IDs: {', '.join(unknown_ids)}")
    evaluations = [
        CaseEvaluation(
            case_id=case.case_id,
            metrics=score_case(case.ground_truth, predictions.get(case.case_id, [])),
        )
        for case in cases
    ]
    truth_characters = sum(item.metrics.truth_characters for item in evaluations)
    predicted_characters = sum(item.metrics.predicted_characters for item in evaluations)
    true_positive_characters = sum(
        item.metrics.true_positive_characters for item in evaluations
    )
    micro_precision, micro_recall, micro_f1 = _rates(
        truth_characters,
        predicted_characters,
        true_positive_characters,
    )
    count = len(evaluations)
    if count:
        macro_precision = sum(item.metrics.precision for item in evaluations) / count
        macro_recall = sum(item.metrics.recall for item in evaluations) / count
        macro_f1 = sum(item.metrics.f1 for item in evaluations) / count
    else:
        macro_precision = macro_recall = macro_f1 = 1.0
    return EvaluationSummary(
        cases=evaluations,
        truth_characters=truth_characters,
        predicted_characters=predicted_characters,
        true_positive_characters=true_positive_characters,
        micro_precision=micro_precision,
        micro_recall=micro_recall,
        micro_f1=micro_f1,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1,
    )
