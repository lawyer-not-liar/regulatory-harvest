import shutil
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from regulatory_harvest.evaluation.legalbench_rag import (
    RetrievedSpan,
    evaluate_spans,
    load_legalbench_dataset,
    score_case,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "legalbench-mini"


def _span(start: int, end: int, *, path: str = "rule.txt") -> RetrievedSpan:
    return RetrievedSpan(file_path=path, start_char=start, end_char=end)


def test_exact_span_metrics() -> None:
    """Changing half-open overlap arithmetic would lower a perfect exact match."""
    metrics = score_case([_span(10, 20)], [_span(10, 20)])

    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0
    assert metrics.true_positive_characters == 10


def test_partial_overlap_scores_characters() -> None:
    """Counting snippets instead of characters would mis-score partial retrieval."""
    metrics = score_case([_span(10, 20)], [_span(15, 25)])

    assert metrics.true_positive_characters == 5
    assert metrics.truth_characters == 10
    assert metrics.predicted_characters == 10
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5


def test_overlapping_predictions_are_merged_before_scoring() -> None:
    """Double-counting overlapping hits could produce recall greater than one."""
    metrics = score_case(
        [_span(10, 20)],
        [_span(10, 18), _span(12, 20)],
    )

    assert metrics.true_positive_characters == 10
    assert metrics.predicted_characters == 10
    assert metrics.recall == 1.0


@pytest.mark.parametrize(
    ("truth", "predicted", "precision", "recall"),
    [
        ([], [], 1.0, 1.0),
        ([_span(0, 1)], [], 0.0, 0.0),
        ([], [_span(0, 1)], 0.0, 0.0),
    ],
)
def test_empty_span_metric_definitions(
    truth: list[RetrievedSpan],
    predicted: list[RetrievedSpan],
    precision: float,
    recall: float,
) -> None:
    """Undefined empty denominators must have stable automation semantics."""
    metrics = score_case(truth, predicted)
    assert metrics.precision == precision
    assert metrics.recall == recall


def test_loader_reads_public_shape_without_retaining_corpus_text() -> None:
    """Evaluation objects must retain spans and queries, not copy the legal corpus."""
    dataset = load_legalbench_dataset(FIXTURE)

    assert dataset.synthetic is True
    assert len(dataset.cases) == 1
    assert dataset.cases[0].case_id == "example.json:0"
    assert dataset.cases[0].query == "What must a controller document?"
    assert dataset.cases[0].ground_truth == [
        RetrievedSpan(file_path="rule.txt", start_char=13, end_char=42)
    ]
    assert "A controller" not in dataset.model_dump_json()


def test_synthetic_marker_does_not_exempt_modified_dataset(tmp_path: Path) -> None:
    """Copying a marker must not bypass terms acknowledgement for different data."""
    copied = tmp_path / "copied-fixture"
    shutil.copytree(FIXTURE, copied)
    benchmark = copied / "benchmarks" / "example.json"
    benchmark.write_text(
        benchmark.read_text(encoding="utf-8").replace(
            "What must a controller document?",
            "What different material applies?",
        ),
        encoding="utf-8",
    )

    assert load_legalbench_dataset(copied).synthetic is False


def test_evaluation_reports_micro_and_macro_metrics_without_text() -> None:
    """Aggregate output must identify cases without embedding source passages."""
    dataset = load_legalbench_dataset(FIXTURE)
    predictions = {dataset.cases[0].case_id: [_span(13, 42)]}

    summary = evaluate_spans(dataset.cases, predictions)

    assert summary.micro_f1 == 1.0
    assert summary.macro_f1 == 1.0
    assert summary.cases[0].case_id == "example.json:0"
    assert "A controller" not in summary.model_dump_json()


def test_loader_rejects_parent_path_reference(tmp_path: Path) -> None:
    """A benchmark path must never escape into unrelated user files."""
    (tmp_path / "corpus").mkdir()
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "outside.txt").write_text("private", encoding="utf-8")
    (tmp_path / "benchmarks" / "bad.json").write_text(
        '{"tests":[{"query":"q","snippets":['
        '{"file_path":"../outside.txt","span":[0,1]}]}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="safe relative"):
        load_legalbench_dataset(tmp_path)


def test_loader_rejects_span_beyond_utf8_text_characters(tmp_path: Path) -> None:
    """Byte or out-of-bounds indexing would make character metrics meaningless."""
    (tmp_path / "corpus").mkdir()
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "corpus" / "rule.txt").write_text("Café", encoding="utf-8")
    (tmp_path / "benchmarks" / "bad.json").write_text(
        '{"tests":[{"query":"q","snippets":['
        '{"file_path":"rule.txt","span":[0,5]}]}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outside corpus text"):
        load_legalbench_dataset(tmp_path)


def test_loader_rejects_corpus_symlink_outside_root(tmp_path: Path) -> None:
    """A corpus symlink must not make the evaluator read unrelated local content."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("private", encoding="utf-8")
    (tmp_path / "corpus").mkdir()
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "corpus" / "linked.txt").symlink_to(outside)
    (tmp_path / "benchmarks" / "bad.json").write_text(
        '{"tests":[{"query":"q","snippets":['
        '{"file_path":"linked.txt","span":[0,1]}]}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outside dataset corpus"):
        load_legalbench_dataset(tmp_path)


@given(
    truth_start=st.integers(min_value=0, max_value=50),
    truth_width=st.integers(min_value=1, max_value=50),
    predicted_start=st.integers(min_value=0, max_value=50),
    predicted_width=st.integers(min_value=1, max_value=50),
)
def test_scores_always_remain_between_zero_and_one(
    truth_start: int,
    truth_width: int,
    predicted_start: int,
    predicted_width: int,
) -> None:
    """Interval combinations must never produce an invalid metric range."""
    metrics = score_case(
        [_span(truth_start, truth_start + truth_width)],
        [_span(predicted_start, predicted_start + predicted_width)],
    )

    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1 <= 1.0


@given(
    start=st.integers(min_value=0, max_value=50),
    width=st.integers(min_value=1, max_value=50),
)
def test_identical_span_sets_always_score_one(start: int, width: int) -> None:
    """Any non-perfect identity score would reveal broken union arithmetic."""
    spans = [_span(start, start + width)]
    metrics = score_case(spans, spans)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


@given(
    width=st.integers(min_value=1, max_value=50),
    false_positive_width=st.integers(min_value=1, max_value=50),
)
def test_adding_false_positive_characters_cannot_improve_precision(
    width: int,
    false_positive_width: int,
) -> None:
    """Additional irrelevant text must not improve retrieval precision."""
    truth = [_span(0, width)]
    baseline = score_case(truth, [_span(0, width)])
    with_false_positive = score_case(
        truth,
        [_span(0, width), _span(width + 1, width + 1 + false_positive_width)],
    )

    assert with_false_positive.precision <= baseline.precision
