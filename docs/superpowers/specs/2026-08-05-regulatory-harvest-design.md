# Regulatory Harvest Design

**Status:** Ready for written-spec review  
**Version:** 0.1  
**Date:** 2026-08-05  
**Audience:** Maintainers, contributors, integrators, and attorneys evaluating the tool  
**Maintenance expectation:** The schema and public interfaces are versioned. Optional integrations may evolve independently, but must preserve bundle compatibility.

## 1. Purpose

Regulatory Harvest is a clean-room, open-source Python toolkit for producing evidence-grounded regulatory research that an attorney can review efficiently. It accepts a defined research request and supplied or retrieved source material, executes a resumable research method called COMBINE, and emits a portable evidence bundle.

The project is storage-neutral. It does not require a server, database, vector store, scheduler, or user interface. A complete run must work from local files and public URLs and persist its state as ordinary files. External systems may store or enrich the same artifacts through adapters.

Regulatory Harvest assists legal research. It does not provide legal advice, determine final legal conclusions, or remove the need for attorney review.

## 2. Product boundary

### 2.1 Version 0.1 includes

- A typed, versioned `ResearchBundle` schema.
- A resumable COMBINE pipeline.
- Intake from local text, Markdown, HTML, and PDF files.
- Intake from explicitly supplied HTTP or HTTPS URLs.
- Source normalization, hashing, provenance, and retrieval metadata.
- Claim-to-source citations using character offsets and quoted source text.
- Deterministic quote verification and structural citation validation.
- Structured findings, gaps, warnings, and attorney-review items.
- JSON bundle export plus a human-readable Markdown report.
- A local filesystem artifact store used by default.
- Interfaces for model, search, source-fetch, and artifact-store providers.
- Optional reference adapters for the OpenAI Responses API and Tavily Search API.
- A first-class cite/OpenContracts adapter implemented against public integration surfaces.
- An optional LegalBench-RAG evaluator that does not redistribute restricted benchmark data.
- A CLI and importable Python API.

### 2.2 Version 0.1 does not include

- A hosted service, web UI, authentication system, or multi-user permissions.
- A bundled statutory or regulatory corpus.
- Continuous monitoring, scheduled freshness sweeps, or alerts.
- A vector database or a requirement to use embeddings.
- Autonomous legal advice or unattended delivery of legal conclusions.
- Employer-specific prompts, workflows, product facts, corpora, identifiers, or infrastructure.
- A replacement for cite/OpenContracts document management, citation graphs, or annotation UI.

## 3. Clean-room requirements

The public implementation must be independently written from this public specification and public sources.

1. Do not copy or mechanically translate non-public source code, workflow exports, prompts, schemas, data, URLs, identifiers, screenshots, or operational records.
2. Do not include confidential facts, credentials, personal data, private corpus material, or employer-specific product descriptions in code, tests, examples, commits, issues, or documentation.
3. Use synthetic examples and public-domain or clearly redistributable fixtures.
4. Record the origin and license of every third-party code or data dependency in `THIRD_PARTY_NOTICES.md` or the relevant fixture manifest.
5. Keep optional benchmark downloads out of the repository. The user must affirm the upstream dataset terms before downloading them.
6. Treat ownership and authorization to publish as a release gate. Technical completion alone does not authorize publication.
7. Preserve the project history. Do not squash away provenance-related corrections before the first public release.

## 4. COMBINE method

COMBINE is both the attorney-facing research method and the engine's checkpointed state machine.

1. **Collect:** Accept source files and URLs, optionally invoke a configured search provider, fetch permitted sources, and record failures without silently dropping them.
2. **Organize:** Normalize source text and record title, URL, jurisdiction, authority type, publication or effective dates when known, retrieval time, content hash, license assertion, and source quality.
3. **Map:** Frame the question into research issues and map relevant sources to those issues. Absence of a source is recorded as a gap, not treated as proof of no law.
4. **Build:** Produce structured findings and claims. Each material factual or legal proposition must either cite one or more source spans or be labeled as uncited analysis.
5. **Inspect:** Verify quote text, citation offsets, source identity, claim support signals, duplicate sources, and coverage. Deterministic failures cannot be overridden by model confidence.
6. **Note:** Record uncertainty, contradictory authority, missing jurisdictions, unavailable sources, temporal ambiguity, provider failures, and attorney-review items.
7. **Export:** Write the canonical JSON bundle, human-readable Markdown report, run manifest, and stage checkpoints.

Each stage reads the prior persisted checkpoint and writes a new checkpoint atomically. Re-running a completed stage with identical inputs is idempotent. A failed stage records a structured error and leaves the last successful checkpoint readable.

## 5. Architecture

### 5.1 Packages

The repository uses a `src/` layout with focused packages:

- `regulatory_harvest.models`: versioned Pydantic domain models and validation rules.
- `regulatory_harvest.combine`: stage protocol, state machine, orchestration, and resume semantics.
- `regulatory_harvest.sources`: local file loading, URL fetching, normalization, hashing, and source-quality assessment.
- `regulatory_harvest.analysis`: provider-neutral issue mapping, claim construction, and report assembly.
- `regulatory_harvest.providers`: optional reference model and search-provider adapters.
- `regulatory_harvest.validation`: deterministic citation, quote, and bundle checks.
- `regulatory_harvest.storage`: artifact-store protocol and atomic filesystem implementation.
- `regulatory_harvest.adapters.cite`: optional cite/OpenContracts API mapping.
- `regulatory_harvest.evaluation.legalbench_rag`: optional benchmark reader and metric calculation.
- `regulatory_harvest.cli`: command-line entry point.

The core packages do not import optional adapters. Optional dependencies are exposed as packaging extras.

### 5.2 Dependency direction

Domain models have no dependency on providers, storage implementations, cite, or LegalBench-RAG. COMBINE depends on domain protocols and models. Adapters depend on core models and their external client libraries. The CLI composes these units but contains no research logic.

### 5.3 Provider protocols

Version 0.1 defines these asynchronous protocols:

- `ModelProvider.complete(request: ModelRequest) -> ModelResponse`
- `SearchProvider.search(query: SearchQuery) -> list[SearchResult]`
- `SourceFetcher.fetch(request: FetchRequest) -> FetchResult`
- `ArtifactStore.read(run_id: str, artifact: str) -> bytes | None`
- `ArtifactStore.write_atomic(run_id: str, artifact: str, data: bytes) -> None`
- `ArtifactStore.list(run_id: str) -> list[str]`

The built-in source fetcher handles supplied local files and HTTP or HTTPS URLs. Search and model providers are optional. A run that only validates and organizes supplied sources must not require an API key.

The reference OpenAI and Tavily adapters are optional extras, configured only through explicit command arguments and environment variables. Custom providers may implement the protocols without depending on either vendor. Prompts and structured-output schemas used by a reference adapter are public, versioned project artifacts.

When no model provider is configured, COMBINE completes Collect and Organize, marks Map and Build as `skipped`, performs every applicable deterministic inspection, records the absence of analysis as a visible gap, and exports a valid source-inventory bundle. It must never present that bundle as completed substantive legal analysis.

## 6. Canonical data contract

### 6.1 `ResearchRequest`

Required fields:

- `request_id`: stable caller-provided or generated identifier.
- `question`: the research question.
- `jurisdictions`: non-empty list of requested jurisdictions.
- `as_of`: date on which the research should be current.
- `source_inputs`: local paths or URLs supplied by the user.

Optional fields include product or factual context, excluded topics, desired output instructions, and provider-specific configuration references. Secrets are never serialized into the request.

### 6.2 `SourceRecord`

Every source has:

- Stable source identifier derived from normalized content and origin metadata.
- Origin URI or local-file display name.
- Retrieval timestamp and SHA-256 content hash.
- Media type, normalized text, and normalization warnings.
- Optional title, publisher, jurisdiction, authority type, citation, effective date, and supersession metadata.
- License assertion with `unknown` as a valid and visible value.
- Source-quality classification: `primary`, `secondary`, `unknown`, or `unusable`.
- Fetch status and structured error when retrieval failed.

### 6.3 `CitationSpan`

A citation points to exactly one `SourceRecord` and contains zero-based, half-open `start_char` and `end_char` offsets into normalized text. It also stores the expected quote text. A valid citation requires:

```text
source.normalized_text[start_char:end_char] == citation.quote
```

Whitespace-tolerant comparison may be reported separately, but it cannot replace the exact result.

### 6.4 `Claim` and `Finding`

A claim contains proposition text, citation identifiers, an `analysis` or `source_supported` classification, a support-check result, confidence as an informational value, and review status. A finding groups claims under an issue, jurisdiction, authority, severity, and practical implication.

Model confidence never changes citation validity. A finding with an invalid material citation must be marked for review.

Model providers propose source identifiers and quote text, not trusted character offsets. The core resolves every proposed quote against normalized source text. If it appears once, the core assigns its exact offsets. If it appears more than once, the model-supplied occurrence number selects the match; an absent or invalid occurrence makes the citation ambiguous and requires review. A quote that does not occur exactly remains an invalid proposed citation and is never silently rewritten.

### 6.5 `ResearchBundle`

The bundle contains:

- Schema version and generator version.
- Research request and run manifest.
- Sources and fetch attempts.
- Issues, findings, claims, and citations.
- Coverage summary and explicit gaps.
- Validation results and attorney-review queue.
- Stage states, timestamps, provider metadata, prompt or configuration fingerprints, and errors.
- Disclaimer and review status.

The canonical JSON representation uses stable ordering where order is not semantically meaningful. Bundle hashing excludes the bundle's own hash field.

## 7. State, errors, and resume behavior

Stages use `pending`, `running`, `completed`, `failed`, and `skipped` states. Only one stage may be `running`. A later stage cannot complete when a required earlier stage is incomplete.

Before starting a stage, COMBINE writes a run manifest update. Stage output is written to a temporary artifact and atomically renamed. On success, the stage becomes `completed`. On failure, the exception is converted to a structured `RunError` containing stage, category, retryability, safe message, and optional provider status code. Tracebacks may be logged locally but are not placed in exported attorney reports.

Resume starts at the earliest required stage that is not completed or whose input fingerprint changed. `--force-stage` invalidates that stage and all dependent stages.

## 8. Deterministic validation

The validation kernel must work without a model provider and must include:

- Schema validation.
- Source hash verification.
- Citation source existence and offset bounds.
- Exact quote verification.
- Normalized-whitespace comparison as a diagnostic.
- Citation identifier uniqueness.
- Claims that reference missing citations.
- Material source-supported claims without citations.
- Jurisdiction coverage against the request.
- Failed or unusable sources surfaced as gaps.
- Required disclaimer and review status.

Claim-support evaluation in version 0.1 uses transparent lexical signals and reports `supported`, `unsupported`, or `indeterminate`. It is a warning or review gate, not a legal entailment judgment.

## 9. Local filesystem behavior

The default run directory is selected by the caller. Regulatory Harvest never writes into a home directory implicitly. A run directory contains:

```text
<run-id>/
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

The source directory stores normalized source artifacts by content hash. The caller may disable raw-content persistence, but normalized text required by a citation must remain embedded in the bundle or reachable through an artifact reference. The report must never claim a citation is verifiable when the cited text is unavailable.

## 10. cite/OpenContracts integration

cite is the first supported external system because its public project exposes corpora, documents, annotations, relationships, authority discovery, and human review surfaces.

The adapter:

- Uses documented GraphQL, REST, or MCP interfaces rather than importing Django models.
- Imports cite documents and annotations into `SourceRecord` and `CitationSpan` objects.
- Exports Harvest findings and source spans as cite-compatible annotations and relationships when the target API permits writes.
- Preserves both Harvest identifiers and cite identifiers as provenance.
- Uses capability detection and fails with an actionable compatibility error when the remote surface lacks a required operation.
- Has contract tests against recorded, sanitized HTTP fixtures and an opt-in live integration suite.

Harvest does not recreate cite's corpus management, citation graph, authority packs, annotation UI, or permissions model.

## 11. LegalBench-RAG evaluation

The optional evaluator reads the upstream corpus and benchmark files from a user-supplied directory. It does not download or redistribute them by default.

The evaluator converts benchmark test cases into retrieval requests and calculates exact-character precision, recall, and F1 from returned spans. A lightweight synthetic fixture tests the adapter in continuous integration. The documentation explains that this benchmark measures retrieval over its supplied legal datasets, not end-to-end regulatory correctness.

## 12. CLI and Python API

The CLI provides:

- `harvest init`: write a safe example request in a caller-selected directory.
- `harvest run`: execute or resume COMBINE.
- `harvest validate`: validate an existing bundle without model or search access.
- `harvest report`: regenerate Markdown from a valid bundle.
- `harvest cite import` and `harvest cite export`: use the optional cite adapter.
- `harvest eval legalbench-rag`: run the optional evaluator against a user-supplied dataset directory.

Every command supports `--json` for machine-readable status and uses non-zero exit codes for invalid input, incomplete runs, validation failures, provider failures, and configuration errors.

The Python API exposes the same operations without shelling out. CLI behavior is a thin composition layer over public functions.

## 13. Security and responsible use

- URL fetches allow HTTP and HTTPS only, reject embedded credentials, enforce byte and time limits, and block local, loopback, link-local, multicast, and private-network destinations by default.
- Redirect targets are revalidated.
- HTML is treated as untrusted input and never executed.
- PDF parsing runs with documented resource limits.
- Provider credentials come from explicit environment variables or caller configuration and are redacted from logs and bundles.
- Reports display source failures, unsupported claims, and human-review requirements.
- The project documentation states that outputs are AI-assisted research work product requiring qualified attorney review.

## 14. Testing and evaluation strategy

Unit tests cover every model invariant, state transition, normalizer, validator, and adapter mapping. Property-based tests cover character offsets, Unicode, whitespace, hashes, and serialization round trips. Integration tests exercise the complete local COMBINE flow from fixtures to JSON and Markdown. Failure tests cover interrupted writes, unavailable URLs, malformed files, SSRF attempts, provider timeouts, invalid checkpoints, and resume behavior.

Release verification requires:

1. The full test suite passes on supported Python versions.
2. Static type checking and linting pass.
3. Package build and installation into a clean environment succeed.
4. The installed CLI completes the synthetic example without network or API keys.
5. The resulting bundle passes `harvest validate`.
6. The clean-room and third-party notices contain no unresolved release blockers.

## 15. Delivery decomposition

Implementation is split into three independently testable plans:

1. **Core and local CLI:** schemas, filesystem store, source intake, deterministic validation, COMBINE, JSON and Markdown output.
2. **cite adapter:** capability detection, import/export mappings, sanitized contract tests, and integration documentation.
3. **LegalBench-RAG and release:** optional evaluator, synthetic fixtures, packaging, security documentation, clean-room audit, and release verification.

The first plan must produce useful, installable software on its own. The second and third plans extend it without changing the canonical bundle contract incompatibly.

## 16. Acceptance criteria

The design is satisfied when a new user can install Regulatory Harvest, create a request referencing local public fixtures, run COMBINE without a server, database, model key, or network access, interrupt and resume the run, inspect a Markdown report, and validate the canonical bundle deterministically. A cite user can exchange sources and findings through the optional adapter. A benchmark user can evaluate retrieval against a separately obtained LegalBench-RAG dataset. All outputs preserve provenance, expose gaps, and require attorney review.
