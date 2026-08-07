# LegalBench-RAG evaluation

Regulatory Harvest includes an optional, storage-neutral evaluator for [LegalBench-RAG](https://github.com/zeroentropy-ai/legalbenchrag). It scores exact character retrieval spans from a dataset you supply. It does not download, bundle, or redistribute LegalBench-RAG data.

LegalBench-RAG evaluates the retrieval step over its legal-contract datasets. A strong score does not establish that a system performs correct end-to-end regulatory research, finds current law, reasons accurately, or produces work that an attorney can rely on.

## Install

The evaluation extra currently adds no packages beyond the base installation:

```bash
python -m pip install "regulatory-harvest[evaluation]"
```

## Obtain and review the dataset separately

Follow the official project's acquisition instructions and review the terms for LegalBench-RAG and its source datasets, including ContractNLI, CUAD, MAUD, and PrivacyQA. Harvest does not automate acceptance, acquisition, generation, or updates.

The supplied root must have this public upstream shape:

```text
dataset/
  corpus/
    ... UTF-8 text files ...
  benchmarks/
    ... JSON benchmark files ...
```

Each benchmark JSON contains `tests`. Each test has a `query`, optional `tags`, and `snippets` containing a corpus-relative `file_path` plus a half-open character `span` such as `[13, 42]`.

Harvest rejects absolute paths, parent traversal, paths outside the dataset through symlinks, non-UTF-8 text, and ranges outside the referenced Python Unicode string. Evaluation results never include corpus text or retrieved quotations.

## Prediction format

Supply UTF-8 JSON Lines with one record per case. Case IDs are deterministic: the benchmark-relative JSON path, a colon, and the zero-based test index.

```json
{"case_id":"privacy_qa.json:0","spans":[{"file_path":"privacy_qa/policy.txt","start_char":120,"end_char":184,"score":0.91}]}
```

`score` is optional and retained only while parsing; character metrics do not use ranking scores. Duplicate case IDs, unknown case IDs, unsafe paths, and out-of-range predictions are errors. A missing case is scored as retrieving no spans.

## Run

For a real dataset, acknowledge that you reviewed and accept the applicable upstream terms:

```bash
harvest eval legalbench-rag \
  --dataset /path/to/data \
  --predictions predictions.jsonl \
  --output results/legalbench-rag.json \
  --config-file retrieval-config.json \
  --accept-upstream-terms \
  --json
```

The optional configuration file must be a JSON object with scalar values. It records the exact retrieval settings associated with the predictions; Harvest does not interpret them.

The exact, fingerprinted synthetic fixture under `tests/fixtures/legalbench-mini` can run without `--accept-upstream-terms` for CI and local verification. Both its marker and its known benchmark/corpus fingerprint must match. Copying the marker or modifying the fixture produces a non-synthetic dataset and requires explicit terms acknowledgement.

## Metrics

Spans are grouped by document and overlapping or adjacent intervals are merged before scoring. This prevents duplicate hits from counting the same character more than once.

- True-positive characters are the intersection of the truth and prediction unions.
- Precision is true-positive characters divided by predicted characters.
- Recall is true-positive characters divided by truth characters.
- F1 is the harmonic mean of precision and recall.
- Micro metrics use character totals across every case.
- Macro metrics average the corresponding per-case values.

When truth and predictions are both empty, precision and recall are `1.0`. If only one side is empty, both are `0.0` for that case.

## Result artifact

The output contains:

- per-case and aggregate metrics;
- the Regulatory Harvest version;
- whether the supplied data matched the known synthetic fixture and whether terms were acknowledged;
- the caller's retrieval configuration;
- dataset-relative paths, byte sizes, and SHA-256 hashes;
- aggregate dataset and predictions fingerprints; and
- an explicit scope limitation.

It contains no dataset root path, corpus text, query answer text, retrieved text, credentials, or model output.

## Python retriever protocol

Applications can bypass JSONL by implementing the asynchronous `Retriever` protocol and calling `run_legalbench_retriever_evaluation`. The retriever receives each `LegalBenchCase` and returns `RetrievedSpan` objects. Harvest still validates every returned path and character range before scoring and writes the same text-free result schema.

## Citation and license boundary

The LegalBench-RAG paper is *LegalBench-RAG: A Benchmark for Retrieval-Augmented Generation in the Legal Domain* by Nicholas Pipitone and Ghita Houir Alami ([arXiv:2408.10343](https://arxiv.org/abs/2408.10343)). Its official code repository is MIT-licensed. Dataset and source-dataset rights are separate; consult the official repository and each source dataset rather than treating the code license as a blanket data license.
