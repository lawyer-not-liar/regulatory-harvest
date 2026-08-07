# Regulatory Harvest LegalBench-RAG and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional LegalBench-RAG evaluator and complete the packaging, clean-room, security, CI, and installation proofs required for a credible public release.

**Architecture:** The evaluator reads a user-supplied benchmark directory and compares exact character spans without downloading or redistributing upstream datasets. Release tooling runs local synthetic fixtures, static checks, package builds, clean-environment installation, and clean-room scans.

**Tech Stack:** Python 3.11+, Pydantic 2, pytest, Hypothesis, Ruff, mypy, hatchling, and GitHub Actions.

## Global Constraints

- Never bundle or automatically download LegalBench-RAG data.
- Require the user to acknowledge upstream dataset terms before evaluating a real dataset.
- State clearly that LegalBench-RAG measures retrieval over its datasets, not end-to-end regulatory correctness.
- CI must use only synthetic, repository-owned fixtures.
- A public release remains blocked until ownership and publication authorization are independently confirmed.
- The installed wheel, not the development checkout, must pass the final offline example.

---

### Task 1: LegalBench-RAG dataset reader and metrics

**Files:**
- Create: `src/regulatory_harvest/evaluation/__init__.py`
- Create: `src/regulatory_harvest/evaluation/legalbench_rag.py`
- Create: `tests/evaluation/test_legalbench_rag.py`
- Create: `tests/fixtures/legalbench-mini/corpus/rule.txt`
- Create: `tests/fixtures/legalbench-mini/benchmarks/example.json`
- Create: `tests/fixtures/legalbench-mini/FIXTURE_LICENSE.md`

**Interfaces:**
- Consumes: user-supplied LegalBench-RAG corpus files, benchmark JSON, and retrieval spans.
- Produces: `LegalBenchCase`, `RetrievedSpan`, `CaseMetrics`, `EvaluationSummary`, `load_legalbench_dataset(path)`, and `evaluate_spans(cases, predictions)`.

- [ ] **Step 1: Write failing exact-character metric tests**

```python
def test_exact_span_metrics() -> None:
    truth = {("rule.txt", 10, 20)}
    predicted = {("rule.txt", 10, 20)}
    metrics = score_case(truth, predicted)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def test_partial_overlap_scores_characters() -> None:
    truth = {("rule.txt", 10, 20)}
    predicted = {("rule.txt", 15, 25)}
    metrics = score_case(truth, predicted)
    assert metrics.true_positive_characters == 5
```

- [ ] **Step 2: Run evaluator tests and verify missing module**

Run: `uv run pytest tests/evaluation/test_legalbench_rag.py -v`  
Expected: collection fails because evaluation modules do not exist.

- [ ] **Step 3: Implement safe dataset loading**

Require `corpus/` and `benchmarks/` beneath the supplied root. Reject absolute paths and `..` in benchmark references. Validate every character range against the referenced UTF-8 text. Do not follow symlinks outside the dataset root. Preserve query and ground-truth spans without copying corpus content into evaluation reports.

- [ ] **Step 4: Implement exact-character aggregation**

Represent spans as per-document integer intervals, merge overlaps within truth and predictions, compute intersection length, and derive micro and macro precision, recall, and F1. Define precision as 1.0 when both truth and prediction are empty, 0.0 when prediction is empty but truth is not, and recall symmetrically.

- [ ] **Step 5: Run evaluator tests and property checks**

Use Hypothesis to prove scores remain within `[0, 1]`, identical sets score 1.0, and adding false-positive characters cannot improve precision. Run: `uv run pytest tests/evaluation -v`  
Expected: all tests pass.

- [ ] **Step 6: Commit evaluator core**

```bash
git add src/regulatory_harvest/evaluation tests/evaluation tests/fixtures/legalbench-mini
git commit -m "feat: evaluate LegalBench-RAG retrieval spans"
```

### Task 2: Evaluator runner and CLI

**Files:**
- Create: `src/regulatory_harvest/evaluation/runner.py`
- Create: `tests/evaluation/test_runner.py`
- Create: `tests/cli/test_eval_cli.py`
- Create: `docs/evaluation.md`
- Modify: `src/regulatory_harvest/cli.py`

**Interfaces:**
- Consumes: dataset reader, metrics, and a configured retrieval callable.
- Produces: `run_legalbench_evaluation`, JSON result files, and `harvest eval legalbench-rag`.

- [ ] **Step 1: Write failing acknowledgement and output tests**

Assert a non-synthetic dataset refuses to run without `--accept-upstream-terms`; synthetic fixture runs without the flag; results identify configuration and package version; and reports contain no corpus text.

- [ ] **Step 2: Run tests and verify missing runner**

Run: `uv run pytest tests/evaluation/test_runner.py tests/cli/test_eval_cli.py -v`  
Expected: collection fails or CLI lacks the evaluator command.

- [ ] **Step 3: Implement evaluator runner**

Accept predictions from JSONL or a `Retriever` protocol. Write per-case metrics and aggregate summary to a caller-selected output. Fingerprint dataset file paths, sizes, and hashes without embedding text. Record that upstream terms were acknowledged and the exact retrieval configuration used.

- [ ] **Step 4: Implement CLI and documentation**

Require `--dataset`, `--predictions`, and `--output`. Add `--accept-upstream-terms` and `--json`. Document upstream acquisition separately, scope limitations, expected prediction format, metric definitions, and citation to the official project.

- [ ] **Step 5: Run evaluator and regression tests**

Run: `uv run pytest tests/evaluation tests/cli/test_eval_cli.py -v && uv run harvest eval legalbench-rag --help`  
Expected: tests pass and help states that the dataset is user supplied.

- [ ] **Step 6: Commit evaluator user surface**

```bash
git add src/regulatory_harvest/evaluation/runner.py src/regulatory_harvest/cli.py tests/evaluation/test_runner.py tests/cli/test_eval_cli.py docs/evaluation.md
git commit -m "feat: add optional LegalBench-RAG runner"
```

### Task 3: Public project metadata and CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `CODE_OF_CONDUCT.md`
- Create: `CHANGELOG.md`
- Create: `CITATION.cff`
- Modify: `pyproject.toml`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `THIRD_PARTY_NOTICES.md`

**Interfaces:**
- Consumes: complete package and test suite.
- Produces: reproducible CI across Python 3.11, 3.12, and 3.13 plus complete package metadata.

- [ ] **Step 1: Add packaging metadata tests**

Create a test that parses `pyproject.toml` and asserts name, version, Python floor, license, repository metadata, CLI entry point, core dependencies, optional extras, and package data for prompts.

- [ ] **Step 2: Run metadata test and verify current gaps**

Run: `uv run pytest tests/test_packaging_metadata.py -v`  
Expected: test fails until metadata is complete.

- [ ] **Step 3: Complete project metadata and public governance files**

Use semantic version `0.1.0`, Apache-2.0 license expression, Python `>=3.11`, classifiers, typed-package marker, project URLs, maintainers, build backend, and optional `openai`, `tavily`, `cite`, and `dev` extras. Do not invent an unavailable GitHub URL; omit repository URLs until remote creation and then add the confirmed value.

- [ ] **Step 4: Add CI workflow**

On pushes and pull requests, install with `uv`, run Ruff, mypy, and pytest with synthetic fixtures only, build distributions, install the wheel in a fresh environment, execute the offline example, and validate its bundle. Pin actions to stable major versions and grant contents read permission only.

- [ ] **Step 5: Run local CI-equivalent commands**

Run: `uv sync --all-extras --dev && uv run ruff check . && uv run mypy src && uv run pytest -q && uv build`  
Expected: all commands exit 0.

- [ ] **Step 6: Commit project metadata and CI**

```bash
git add .github pyproject.toml README.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md CODE_OF_CONDUCT.md CHANGELOG.md CITATION.cff tests/test_packaging_metadata.py
git commit -m "chore: prepare Regulatory Harvest for public CI"
```

### Task 4: Clean-room, secret, and provenance audit

**Files:**
- Create: `scripts/audit_release.py`
- Create: `tests/scripts/test_audit_release.py`
- Create: `docs/release-checklist.md`
- Modify: `CLEAN_ROOM.md`
- Modify: `SECURITY.md`

**Interfaces:**
- Consumes: tracked repository contents and third-party notices.
- Produces: deterministic local release-audit command with machine-readable findings.

- [ ] **Step 1: Write failing audit-script tests**

Create temporary repositories containing a fake secret, private host, absolute user path, legacy internal identifier, unlicensed fixture, and prohibited generated export. Assert each produces a stable finding code. Assert the real clean synthetic fixture tree passes.

- [ ] **Step 2: Run audit tests and verify missing script**

Run: `uv run pytest tests/scripts/test_audit_release.py -v`  
Expected: test fails because the audit script does not exist.

- [ ] **Step 3: Implement tracked-file audit**

Read paths from `git ls-files -z`; scan text files only; reject common secret formats, private-network URLs, absolute home paths, prohibited legacy project names, workflow-export fingerprints, and fixture files lacking a nearby license manifest. Allow documented synthetic sentinel strings only inside audit tests. Emit JSON and human-readable results without printing discovered secret values.

- [ ] **Step 4: Document the human authorization gate**

The checklist separates automated technical checks from the non-automatable ownership/publication authorization. It requires the repository owner to record that confirmation outside the codebase before creating a public remote. The audit reports this item as `MANUAL_CONFIRMATION_REQUIRED`, not as a technical pass.

- [ ] **Step 5: Run audit and commit**

Run: `uv run pytest tests/scripts/test_audit_release.py -v && uv run python scripts/audit_release.py --json`  
Expected: tests pass; the real repository has no automated findings and reports one manual authorization requirement.

```bash
git add scripts/audit_release.py tests/scripts/test_audit_release.py docs/release-checklist.md CLEAN_ROOM.md SECURITY.md
git commit -m "chore: add clean-room release audit"
```

### Task 5: Final installation and acceptance audit

**Files:**
- Create: `docs/verification/0.1.0.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: built distributions, complete docs, tests, CLI, cite contract fixtures, and evaluator fixtures.
- Produces: evidence-backed verification record for version 0.1.0.

- [ ] **Step 1: Run every automated gate from a clean checkout state**

Run: `git status --short`, `uv sync --all-extras --dev`, `uv run ruff check .`, `uv run mypy src`, `uv run pytest -q`, `uv build`, and `uv run python scripts/audit_release.py --json`. Record exact commands, versions, and summarized outputs in the verification document.

- [ ] **Step 2: Verify the built wheel in a new temporary environment**

Create a temporary virtual environment outside the repository, install only the wheel, copy the offline example, run `harvest run`, `harvest validate`, and `harvest report`, then compare regenerated Markdown and validation status. Record output hashes.

- [ ] **Step 3: Verify optional extras in isolated environments**

Install wheel extras separately for `cite` and evaluator dependencies. Run cite contract tests without a live server and the synthetic LegalBench-RAG evaluation. Confirm base installation imports without either extra.

- [ ] **Step 4: Audit each design acceptance criterion**

For every item in design sections 2, 3, 4, 7, 8, 10, 11, 12, 13, 14, and 16, cite a test, command output, artifact, or documented manual gate. Mark missing evidence as incomplete and continue implementation until all technical criteria are proven.

- [ ] **Step 5: Update changelog and commit verification evidence**

```bash
git add docs/verification/0.1.0.md CHANGELOG.md
git commit -m "docs: record 0.1.0 verification evidence"
```

- [ ] **Step 6: Stop before external publication if authorization is unconfirmed**

Do not create or publish a GitHub repository until the repository owner explicitly confirms the manual ownership/publication authorization gate and asks to publish. Local version 0.1.0 may be technically complete while external publication remains intentionally pending.
