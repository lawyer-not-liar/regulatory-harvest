"""Optional evaluation helpers for user-supplied benchmark data."""

from .legalbench_rag import (
    CaseEvaluation,
    CaseMetrics,
    EvaluationSummary,
    LegalBenchCase,
    LegalBenchDataset,
    RetrievedSpan,
    evaluate_spans,
    load_legalbench_dataset,
    score_case,
    validate_prediction_spans,
)
from .runner import (
    DatasetFileFingerprint,
    LegalBenchEvaluationResult,
    PredictionRecord,
    Retriever,
    UpstreamTermsNotAcceptedError,
    run_legalbench_evaluation,
    run_legalbench_retriever_evaluation,
)

__all__ = [
    "CaseEvaluation",
    "CaseMetrics",
    "DatasetFileFingerprint",
    "EvaluationSummary",
    "LegalBenchCase",
    "LegalBenchDataset",
    "LegalBenchEvaluationResult",
    "PredictionRecord",
    "RetrievedSpan",
    "Retriever",
    "UpstreamTermsNotAcceptedError",
    "evaluate_spans",
    "load_legalbench_dataset",
    "run_legalbench_evaluation",
    "run_legalbench_retriever_evaluation",
    "score_case",
    "validate_prediction_spans",
]
