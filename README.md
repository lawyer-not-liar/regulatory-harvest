# Regulatory Harvest

Regulatory Harvest is a clean-room Python toolkit for producing evidence-grounded regulatory research bundles that attorneys can review. It accepts local files and supplied public URLs, runs the resumable COMBINE method, and exports portable JSON plus a human-readable Markdown report.

Regulatory Harvest assists research. It does not provide legal advice or replace source review, currentness checks, professional judgment, or a qualified attorney.

## What makes it useful

- Runs locally without a server, database, vector store, model key, or network connection.
- Keeps normalized source text, hashes, provenance, gaps, and review items in a versioned bundle.
- Seals terminal bundles with a canonical SHA-256 hash that excludes only its own hash field.
- Resolves proposed quotations to exact character offsets in trusted core code.
- Rejects missing, ambiguous, altered, or out-of-bounds citations deterministically.
- Checkpoints every COMBINE stage and resumes without repeating completed work.
- Lets callers choose storage, model, search, and source-fetch implementations through typed protocols.
- Offers optional OpenAI Responses API and Tavily Search reference adapters.
- Exchanges evidence with cite through an optional, capability-aware public-interface adapter.

## Install

Regulatory Harvest requires Python 3.11 or newer.

```bash
python -m pip install regulatory-harvest
```

For development from a clone:

```bash
python -m pip install uv
uv sync --frozen
uv run harvest --help
```

## Five-minute offline example

Copy `examples/offline` to a writable directory, then run:

```bash
cd examples/offline
harvest run --request request.json --output runs
harvest validate runs/offline-example/bundle.json --json
harvest report runs/offline-example/bundle.json --output runs/offline-example/report.md
```

The example is synthetic and requires no network, API key, server, or database. Because no model provider is configured, Map and Build are visibly marked `skipped`, the absence of substantive analysis is recorded as a gap, and the source-inventory bundle still validates.

`harvest validate` and `harvest report` recompute the bundle hash and all deterministic checks. A missing or changed terminal-bundle hash returns exit code `4`; `report` still renders the validation failures for review instead of repeating stored validation state.

To start a new project:

```bash
harvest init my-research
```

Edit `my-research/request.json`, add the referenced files, and choose an output directory when running.

## COMBINE

COMBINE is both the research method and the persisted state machine:

1. **Collect** supplied sources and optional search results without silently dropping failures.
2. **Organize** normalized text and provenance while deduplicating content sent for analysis.
3. **Map** the research question into issues when a model provider is configured.
4. **Build** findings, analytical claims, and proposed exact quotations.
5. **Inspect** hashes, citation closure, exact quote spans, lexical support, and jurisdiction coverage.
6. **Note** gaps, source failures, invalid evidence, and attorney-review items.
7. **Export** the bundle, report, manifest, and stage checkpoints.

Each run is stored beneath the caller-selected output directory:

```text
<output>/<run-id>/
  request.json
  manifest.json
  checkpoints/
    collect.json
    organize.json
    map.json
    build.json
    inspect.json
    note.json
    export.json
  bundle.json
  report.md
```

Use `--force-stage organize` to rerun one stage and every dependent stage. Use `--clear-stale-lock` only after confirming that no process still owns the run.

## Python API

```python
from pathlib import Path

from regulatory_harvest.api import run_research_sync, validate_research_bundle

result = run_research_sync(Path("request.json"), Path("runs"))
report = validate_research_bundle(Path("runs") / result.manifest.run_id / "bundle.json")
assert report.valid
```

Use the asynchronous `run_research` function in applications that already have an event loop. The synchronous wrapper refuses to nest an active event loop.

## Optional providers

The base installation stays offline. See [docs/providers.md](docs/providers.md) for the OpenAI and Tavily adapters, their privacy boundaries, and custom provider protocols.

```bash
python -m pip install "regulatory-harvest[openai]"
```

Reference providers must be enabled explicitly. Source excerpts sent to a model or search context sent to a search provider leave the local machine. Credentials never belong in requests, bundles, reports, fixtures, or configuration fingerprints.

## cite and evaluation adapters

The optional [cite/OpenContracts adapter](docs/integrations/cite.md) exchanges source, annotation, and relationship records through documented MCP and GraphQL interfaces. Install it with `python -m pip install "regulatory-harvest[cite]"`. The optional [LegalBench-RAG evaluator](docs/evaluation.md) reads a separately obtained dataset directory, scores exact-character retrieval, and does not redistribute benchmark data. It does not measure end-to-end regulatory correctness.

## Important limitations

- A valid offline source-inventory bundle is not completed legal analysis.
- Exact quotation proves textual identity, not legal entailment, applicability, or currentness.
- Lexical support is a transparent warning signal, not a legal reasoning score.
- Source metadata may be unknown or caller-declared and always requires verification.
- URL protections reduce SSRF risk but do not make arbitrary URLs safe in a privileged network.
- PDF parsers process untrusted input; isolate high-risk workflows appropriately.
- Regulatory Harvest does not ship a regulatory corpus or monitor changes over time.
- Attorney review is mandatory for every version 1.0 bundle.

## Development

```bash
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
```

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CLEAN_ROOM.md](CLEAN_ROOM.md), and [SECURITY.md](SECURITY.md) before contributing. Tests and examples may use only synthetic or clearly redistributable material.

## License

Regulatory Harvest is licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
