import json
import shutil
from pathlib import Path

import pytest

from regulatory_harvest.evaluation.runner import (
    UpstreamTermsNotAcceptedError,
    run_legalbench_evaluation,
    run_legalbench_retriever_evaluation,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "legalbench-mini"


def test_synthetic_fixture_runs_without_upstream_terms_flag(tmp_path: Path) -> None:
    """Repository-owned synthetic data should remain usable in offline CI."""
    output = tmp_path / "result.json"

    result = run_legalbench_evaluation(
        FIXTURE,
        FIXTURE / "predictions.jsonl",
        output,
        accept_upstream_terms=False,
        retrieval_configuration={"method": "synthetic-exact", "top_k": 1},
    )

    assert result.synthetic_fixture is True
    assert result.upstream_terms_acknowledged is False
    assert result.package_version == "0.1.0"
    assert result.retrieval_configuration == {
        "method": "synthetic-exact",
        "top_k": 1,
    }
    assert result.summary.micro_f1 == 1.0
    assert output.exists()


def test_real_shaped_dataset_requires_explicit_terms_acknowledgement(
    tmp_path: Path,
) -> None:
    """A copied real dataset must not be evaluated on implicit upstream terms."""
    dataset = tmp_path / "dataset"
    shutil.copytree(FIXTURE, dataset)
    (dataset / "FIXTURE_LICENSE.md").unlink()
    output = tmp_path / "result.json"

    with pytest.raises(UpstreamTermsNotAcceptedError, match="upstream dataset terms"):
        run_legalbench_evaluation(
            dataset,
            dataset / "predictions.jsonl",
            output,
            accept_upstream_terms=False,
            retrieval_configuration={},
        )

    assert not output.exists()


def test_result_fingerprints_inputs_without_copying_corpus_text(tmp_path: Path) -> None:
    """A shareable evaluation result must not redistribute benchmark corpus content."""
    output = tmp_path / "result.json"

    result = run_legalbench_evaluation(
        FIXTURE,
        FIXTURE / "predictions.jsonl",
        output,
        accept_upstream_terms=False,
        retrieval_configuration={"chunk_size": 256},
    )

    serialized = output.read_text(encoding="utf-8")
    assert "A controller must document" not in serialized
    assert str(FIXTURE) not in serialized
    assert result.dataset_fingerprint
    assert result.predictions_fingerprint
    assert {item.relative_path for item in result.dataset_files} == {
        "benchmarks/example.json",
        "corpus/rule.txt",
    }
    assert all(len(item.sha256) == 64 for item in result.dataset_files)
    assert json.loads(serialized)["benchmark"] == "LegalBench-RAG"


def test_runner_rejects_prediction_span_outside_corpus(tmp_path: Path) -> None:
    """Invalid predictions must not be scored against nonexistent characters."""
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text(
        '{"case_id":"example.json:0","spans":['
        '{"file_path":"rule.txt","start_char":0,"end_char":999}]}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outside corpus text"):
        run_legalbench_evaluation(
            FIXTURE,
            predictions,
            tmp_path / "result.json",
            accept_upstream_terms=False,
            retrieval_configuration={},
        )


class _ExactRetriever:
    async def retrieve(self, case):
        return case.ground_truth


@pytest.mark.asyncio
async def test_runner_accepts_configured_retriever_protocol(tmp_path: Path) -> None:
    """Applications should evaluate a retriever without first inventing JSONL storage."""
    result = await run_legalbench_retriever_evaluation(
        FIXTURE,
        _ExactRetriever(),
        tmp_path / "retriever-result.json",
        accept_upstream_terms=False,
        retrieval_configuration={"method": "exact-test-double"},
    )

    assert result.summary.micro_f1 == 1.0
    assert result.predictions_fingerprint
