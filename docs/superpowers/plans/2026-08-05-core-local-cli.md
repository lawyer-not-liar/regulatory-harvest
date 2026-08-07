# Regulatory Harvest Core and Local CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an installable Python package that runs the resumable COMBINE method against local files and supplied URLs, exports a portable evidence bundle and Markdown report, and validates both without a server, database, network, or model key.

**Architecture:** Pydantic models define the canonical bundle. Small source, storage, validation, analysis, and orchestration modules communicate through typed protocols. The CLI composes those modules while the filesystem adapter persists atomic checkpoints and final artifacts.

**Tech Stack:** Python 3.11+, Pydantic 2, httpx, Beautiful Soup 4, pypdf, argparse, hatchling, pytest, pytest-asyncio, Hypothesis, respx, Ruff, and mypy.

## Global Constraints

- Use a `src/` package layout and expose the `harvest` console command.
- A local-file-only run must not require a server, database, network, search provider, model provider, or API key.
- The caller selects every output directory; never write implicitly to a home directory.
- Do not copy or mechanically translate non-public code, prompts, workflow exports, schemas, data, URLs, or identifiers.
- Use only synthetic or clearly redistributable fixtures.
- Persist checkpoints atomically and make completed stages idempotent for identical input fingerprints.
- Model confidence never changes deterministic citation validity.
- Material source-supported claims with invalid or missing citations require review.
- Every exported report includes the attorney-review disclaimer.
- Python core packages must not import cite/OpenContracts or LegalBench-RAG adapters.

---

### Task 1: Package scaffold and canonical models

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `src/regulatory_harvest/__init__.py`
- Create: `src/regulatory_harvest/models/enums.py`
- Create: `src/regulatory_harvest/models/request.py`
- Create: `src/regulatory_harvest/models/source.py`
- Create: `src/regulatory_harvest/models/analysis.py`
- Create: `src/regulatory_harvest/models/run.py`
- Create: `src/regulatory_harvest/models/bundle.py`
- Create: `src/regulatory_harvest/models/__init__.py`
- Create: `tests/models/test_models.py`

**Interfaces:**
- Consumes: The approved design's canonical data contract.
- Produces: `ResearchRequest`, `SourceInput`, `SourceRecord`, `CitationSpan`, `Claim`, `Finding`, `Gap`, `ReviewItem`, `StageRecord`, `RunManifest`, `ValidationIssue`, `ValidationReport`, and `ResearchBundle`.

- [ ] **Step 1: Write model tests before model code**

```python
def test_request_requires_jurisdiction() -> None:
    with pytest.raises(ValidationError):
        ResearchRequest(
            request_id="demo",
            question="What does the rule require?",
            jurisdictions=[],
            as_of=date(2026, 8, 5),
            source_inputs=[SourceInput(location="rule.txt")],
        )


def test_citation_uses_half_open_offsets() -> None:
    citation = CitationSpan(
        citation_id="cite-1",
        source_id="source-1",
        start_char=4,
        end_char=8,
        quote="must",
    )
    assert citation.end_char - citation.start_char == len(citation.quote)


def test_bundle_round_trip_is_lossless(sample_bundle: ResearchBundle) -> None:
    restored = ResearchBundle.model_validate_json(sample_bundle.model_dump_json())
    assert restored == sample_bundle
```

- [ ] **Step 2: Run the model tests and verify import failures**

Run: `uv run pytest tests/models/test_models.py -v`  
Expected: collection fails because `regulatory_harvest.models` does not exist.

- [ ] **Step 3: Add packaging metadata and implement the models**

Use Python string enums for `StageName`, `StageStatus`, `SourceQuality`, `FetchStatus`, `ClaimKind`, `SupportStatus`, `ReviewStatus`, `Severity`, and `IssueLevel`. Configure every public Pydantic model with `extra="forbid"`. Require non-blank request identifiers, questions, jurisdictions, source locations, source identifiers, and claim text. Validate half-open offsets with `0 <= start_char < end_char`. Give `SourceRecord`, `CitationSpan`, `Claim`, and `Finding` an `external_ids: dict[str, str]` field for adapter provenance. Give `SourceInput` explicit optional `title`, `jurisdiction`, `authority_type`, `citation`, `source_quality`, and `license` metadata. Define `ResearchBundle.schema_version` as the literal `"1.0"` and include the fixed disclaimer:

```text
AI-assisted research work product. A qualified attorney must verify the sources, analysis, currentness, and applicability before relying on it or delivering legal advice.
```

Set `requires_attorney_review=True` by default and reject attempts to set it false in schema version 1.0.

- [ ] **Step 4: Run focused model tests**

Run: `uv run pytest tests/models/test_models.py -v`  
Expected: all model tests pass.

- [ ] **Step 5: Run formatting and type checks for the new package**

Run: `uv run ruff check src/regulatory_harvest/models tests/models && uv run mypy src/regulatory_harvest/models`  
Expected: both commands exit 0.

- [ ] **Step 6: Commit the canonical contract**

```bash
git add pyproject.toml .gitignore LICENSE src/regulatory_harvest tests/models
git commit -m "feat: define Regulatory Harvest bundle schema"
```

### Task 2: Atomic artifact store and deterministic serialization

**Files:**
- Create: `src/regulatory_harvest/storage/base.py`
- Create: `src/regulatory_harvest/storage/filesystem.py`
- Create: `src/regulatory_harvest/storage/serialization.py`
- Create: `src/regulatory_harvest/storage/__init__.py`
- Create: `tests/storage/test_filesystem.py`
- Create: `tests/storage/test_serialization.py`

**Interfaces:**
- Consumes: `ResearchBundle` and `RunManifest` from Task 1.
- Produces: asynchronous `ArtifactStore` protocol, `FileSystemArtifactStore`, `canonical_json_bytes(value)`, and `sha256_digest(data)`.

- [ ] **Step 1: Write failing atomic-write and canonical-serialization tests**

```python
@pytest.mark.asyncio
async def test_write_atomic_never_leaves_temp_file(tmp_path: Path) -> None:
    store = FileSystemArtifactStore(tmp_path)
    await store.write_atomic("run-1", "manifest.json", b'{"ok":true}')
    assert await store.read("run-1", "manifest.json") == b'{"ok":true}'
    assert list(tmp_path.rglob("*.tmp")) == []


def test_canonical_json_sorts_mapping_keys() -> None:
    assert canonical_json_bytes({"z": 1, "a": 2}) == b'{"a":2,"z":1}'
```

- [ ] **Step 2: Run tests to confirm missing modules**

Run: `uv run pytest tests/storage -v`  
Expected: collection fails because `regulatory_harvest.storage` does not exist.

- [ ] **Step 3: Implement safe artifact paths and atomic replacement**

Reject absolute artifact names and any path containing `..`. Resolve every artifact beneath `<root>/<run_id>/`. Write to a sibling temporary file opened with exclusive creation, flush and `os.fsync`, then replace with `os.replace`. Implement `read`, `write_atomic`, and sorted `list`. Serialize Pydantic models with aliases excluded only when explicitly requested, UTF-8, sorted keys, compact separators, and a trailing newline only for human-facing files.

- [ ] **Step 4: Test interrupted writes and traversal attempts**

Add tests that monkeypatch `os.replace` to raise, assert the prior artifact remains unchanged, and assert `../secret` and absolute artifact paths raise `UnsafeArtifactPathError`.

- [ ] **Step 5: Run storage tests and checks**

Run: `uv run pytest tests/storage -v && uv run ruff check src/regulatory_harvest/storage tests/storage && uv run mypy src/regulatory_harvest/storage`  
Expected: all commands exit 0.

- [ ] **Step 6: Commit storage primitives**

```bash
git add src/regulatory_harvest/storage tests/storage
git commit -m "feat: add atomic filesystem artifact store"
```

### Task 3: Safe local and URL source intake

**Files:**
- Create: `src/regulatory_harvest/sources/security.py`
- Create: `src/regulatory_harvest/sources/normalize.py`
- Create: `src/regulatory_harvest/sources/fetch.py`
- Create: `src/regulatory_harvest/sources/quality.py`
- Create: `src/regulatory_harvest/sources/__init__.py`
- Create: `tests/sources/test_security.py`
- Create: `tests/sources/test_normalize.py`
- Create: `tests/sources/test_fetch.py`
- Create: `tests/fixtures/public-rule.txt`
- Create: `tests/fixtures/public-rule.html`
- Create: `tests/fixtures/FIXTURE_LICENSES.md`

**Interfaces:**
- Consumes: `SourceInput`, `SourceRecord`, `FetchStatus`, and `SourceQuality` from Task 1.
- Produces: `validate_public_url(url)`, `normalize_content(data, media_type)`, `classify_source_quality(metadata)`, and asynchronous `DefaultSourceFetcher.fetch(source_input)`.

- [ ] **Step 1: Write URL-security and normalization tests**

```python
@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "https://user:pass@example.org/rule",
    ],
)
def test_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(UnsafeSourceError):
        validate_public_url(url)


def test_html_normalization_removes_scripts() -> None:
    normalized = normalize_content(
        b"<h1>Rule</h1><script>alert(1)</script><p>A controller must act.</p>",
        "text/html",
    )
    assert normalized.text == "Rule\nA controller must act."
    assert "alert" not in normalized.text
```

- [ ] **Step 2: Run source tests and verify failures**

Run: `uv run pytest tests/sources -v`  
Expected: collection fails because source modules do not exist.

- [ ] **Step 3: Implement URL validation and redirect revalidation**

Accept only `http` and `https`; reject credentials and missing hosts. Resolve all host addresses with `socket.getaddrinfo` and reject unspecified, loopback, private, link-local, multicast, and reserved IPs using `ipaddress`. Disable automatic redirects in httpx; validate each `Location` before following at most five redirects. Enforce a 20-second timeout and a 10 MiB body limit by streaming bytes.

- [ ] **Step 4: Implement local loading and normalization**

Support `.txt`, `.md`, `.html`, `.htm`, and `.pdf`. Decode text with UTF-8 and fail visibly on invalid data. Use Beautiful Soup with the standard `html.parser`; remove `script`, `style`, `noscript`, and `template`; emit block text separated by single newlines. Extract PDF text with pypdf and record page-level extraction warnings. Normalize line endings to `\n`, Unicode to NFC, trailing whitespace per line, and runs of more than two blank lines to two. Do not collapse intra-line whitespace because citation offsets refer to normalized text.

- [ ] **Step 5: Create `SourceRecord` values and quality labels**

Generate `source_id` as `src_` plus the first 24 hexadecimal characters of SHA-256 over canonical origin plus normalized content hash. Set `primary` only when explicitly declared by the caller; set `secondary` only when declared; otherwise use `unknown`. Empty normalized text is `unusable`. Failed fetches remain `SourceRecord` entries with structured errors and no fabricated content.

- [ ] **Step 6: Run source tests and security checks**

Run: `uv run pytest tests/sources -v && uv run ruff check src/regulatory_harvest/sources tests/sources && uv run mypy src/regulatory_harvest/sources`  
Expected: all commands exit 0.

- [ ] **Step 7: Commit source intake**

```bash
git add src/regulatory_harvest/sources tests/sources tests/fixtures
git commit -m "feat: add safe source intake and normalization"
```

### Task 4: Citation resolution and deterministic validation kernel

**Files:**
- Create: `src/regulatory_harvest/validation/citations.py`
- Create: `src/regulatory_harvest/validation/support.py`
- Create: `src/regulatory_harvest/validation/bundle.py`
- Create: `src/regulatory_harvest/validation/__init__.py`
- Create: `tests/validation/test_citations.py`
- Create: `tests/validation/test_support.py`
- Create: `tests/validation/test_bundle.py`

**Interfaces:**
- Consumes: source, claim, citation, request, and bundle models from Task 1.
- Produces: `resolve_quote(source, quote, occurrence=None)`, `check_claim_support(claim, citations, sources)`, and `validate_bundle(bundle) -> ValidationReport`.

- [ ] **Step 1: Write failing quote-resolution tests**

```python
def test_unique_quote_resolves_exact_offsets() -> None:
    result = resolve_quote("A controller must document risks.", "must document")
    assert result.start_char == 13
    assert result.end_char == 26
    assert result.exact is True


def test_repeated_quote_without_occurrence_is_ambiguous() -> None:
    result = resolve_quote("must act; must report", "must")
    assert result.ambiguous is True
    assert result.start_char is None
```

- [ ] **Step 2: Write failing bundle-validation tests**

Test missing sources, out-of-bounds spans, mismatched quotes, duplicate citation IDs, source-supported claims without citations, failed sources absent from gaps, missing jurisdictions, altered source hashes, and missing disclaimer. Assert stable issue codes such as `CITATION_SOURCE_MISSING`, `QUOTE_MISMATCH`, `SOURCE_HASH_MISMATCH`, `MATERIAL_CLAIM_UNCITED`, and `JURISDICTION_UNCOVERED`.

- [ ] **Step 3: Run validation tests and confirm failures**

Run: `uv run pytest tests/validation -v`  
Expected: collection fails because validation modules do not exist.

- [ ] **Step 4: Implement quote resolution and citation checks**

Use exact Python substring search. Return all match positions internally. A unique match resolves automatically; multiple matches require a one-based occurrence; no match remains invalid. Separately calculate a whitespace-normalized diagnostic but never mutate the quote or declare exact verification from it.

- [ ] **Step 5: Implement transparent lexical support checks**

Tokenize Unicode words case-insensitively, retain digit-bearing tokens, remove a documented English stop-word set, and compute the proportion of claim content tokens present in the union of cited quotes. Return `indeterminate` for fewer than four content tokens, `supported` at coverage `>= 0.60`, and `unsupported` below that. If claim and support differ on explicit `not`, `no`, `never`, or `without` markers at coverage `>= 0.80`, return `unsupported` with reason `polarity_mismatch`.

- [ ] **Step 6: Implement bundle-wide validation**

Produce stable, sorted issues with path, level, code, message, and related identifiers. Error-level issues make `ValidationReport.valid=False`. Warning-level issues preserve validity but keep `requires_attorney_review=True`. Recompute source hashes from normalized text. Ensure every requested jurisdiction appears in a finding or explicit gap.

- [ ] **Step 7: Run validation and property tests**

Add Hypothesis tests proving every resolved exact citation slices back to the same quote and that canonical serialization round-trips Unicode offsets. Run: `uv run pytest tests/validation -v`  
Expected: all validation tests pass.

- [ ] **Step 8: Commit validation kernel**

```bash
git add src/regulatory_harvest/validation tests/validation
git commit -m "feat: verify citations and evidence bundles"
```

### Task 5: Analysis drafts and provider protocols

**Files:**
- Create: `src/regulatory_harvest/providers/protocols.py`
- Create: `src/regulatory_harvest/providers/__init__.py`
- Create: `src/regulatory_harvest/analysis/drafts.py`
- Create: `src/regulatory_harvest/analysis/build.py`
- Create: `src/regulatory_harvest/analysis/__init__.py`
- Create: `tests/analysis/test_build.py`
- Create: `tests/providers/test_protocols.py`

**Interfaces:**
- Consumes: `ResearchRequest`, `SourceRecord`, `CitationSpan`, `Claim`, and `Finding`.
- Produces: `ModelProvider`, `SearchProvider`, `SourceFetcher`, `ModelRequest`, `ModelResponse`, `SearchQuery`, `SearchResult`, `AnalysisDraft`, `ProposedCitation`, and `build_analysis(draft, sources)`.

- [ ] **Step 1: Write failing draft-resolution tests**

```python
def test_build_resolves_model_quote_in_core(source_record: SourceRecord) -> None:
    draft = AnalysisDraft(
        issues=[DraftIssue(issue_id="issue-1", title="Documentation")],
        findings=[
            DraftFinding(
                finding_id="finding-1",
                issue_id="issue-1",
                jurisdiction="US",
                authority="Example Rule",
                severity="medium",
                practical_implication="Maintain written records.",
                claims=[
                    DraftClaim(
                        claim_id="claim-1",
                        text="The rule requires documentation.",
                        kind="source_supported",
                        proposed_citations=[
                            ProposedCitation(
                                source_id=source_record.source_id,
                                quote="must document risks",
                            )
                        ],
                    )
                ],
            )
        ],
    )
    result = build_analysis(draft, [source_record])
    assert result.citations[0].quote == "must document risks"
```

- [ ] **Step 2: Run tests and verify missing modules**

Run: `uv run pytest tests/analysis tests/providers -v`  
Expected: collection fails because analysis and provider modules do not exist.

- [ ] **Step 3: Define provider-neutral request and result models**

`ModelRequest` includes operation, versioned system instructions, JSON schema, source excerpts, and safe metadata. `ModelResponse` includes parsed output, provider name, model name, response identifier, usage, and prompt fingerprint, but never credentials. `SearchResult` includes URL, title, snippet, provider rank, and optional publication date.

- [ ] **Step 4: Implement model-output conversion without trusting offsets**

Resolve every proposed quote with Task 4's resolver. When no exact match exists or occurrence is ambiguous, do not create a `CitationSpan`; preserve the rejected `ProposedCitation` inside a review item's structured context. Preserve uncited `analysis` claims. Reject a source-supported claim whose proposed source identifier does not exist. Run lexical support checks after resolution.

- [ ] **Step 5: Run analysis tests and checks**

Run: `uv run pytest tests/analysis tests/providers -v && uv run ruff check src/regulatory_harvest/analysis src/regulatory_harvest/providers tests/analysis tests/providers && uv run mypy src/regulatory_harvest/analysis src/regulatory_harvest/providers`  
Expected: all commands exit 0.

- [ ] **Step 6: Commit provider protocols and analysis conversion**

```bash
git add src/regulatory_harvest/analysis src/regulatory_harvest/providers tests/analysis tests/providers
git commit -m "feat: add provider-neutral analysis drafts"
```

### Task 6: Resumable COMBINE engine

**Files:**
- Create: `src/regulatory_harvest/combine/fingerprints.py`
- Create: `src/regulatory_harvest/combine/stages.py`
- Create: `src/regulatory_harvest/combine/engine.py`
- Create: `src/regulatory_harvest/combine/__init__.py`
- Create: `tests/combine/test_engine.py`
- Create: `tests/combine/test_resume.py`

**Interfaces:**
- Consumes: models, source fetcher, artifact store, analysis builder, validation kernel, and optional providers.
- Produces: `CombineEngine`, `CombineDependencies`, `RunResult`, `run(request, force_stage=None)`, and stage checkpoint artifacts.

- [ ] **Step 1: Write failing state-transition tests**

```python
@pytest.mark.asyncio
async def test_offline_run_completes_with_visible_analysis_gap(engine, request) -> None:
    result = await engine.run(request)
    assert result.manifest.stage("collect").status == StageStatus.COMPLETED
    assert result.manifest.stage("organize").status == StageStatus.COMPLETED
    assert result.manifest.stage("map").status == StageStatus.SKIPPED
    assert any(gap.code == "MODEL_PROVIDER_NOT_CONFIGURED" for gap in result.bundle.gaps)


@pytest.mark.asyncio
async def test_resume_does_not_repeat_completed_collect(engine, request, fetcher) -> None:
    await engine.run(request)
    await engine.run(request)
    assert fetcher.calls == len(request.source_inputs)
```

- [ ] **Step 2: Write failing interruption and force-stage tests**

Inject a stage implementation that fails during Build, then assert Collect, Organize, and Map checkpoints remain readable; resume executes Build onward only. Force Organize and assert Organize plus all dependent stages rerun while Collect remains unchanged.

- [ ] **Step 3: Run engine tests and confirm missing modules**

Run: `uv run pytest tests/combine -v`  
Expected: collection fails because `regulatory_harvest.combine` does not exist.

- [ ] **Step 4: Implement fingerprints and state invariants**

Fingerprint each stage from its canonical input model, implementation version, and relevant provider configuration fingerprint. Exclude timestamps and credentials. Enforce only one `running` stage. Before stage execution, atomically persist the manifest with `running`; on success, persist the checkpoint and then `completed`; on failure, persist a safe `RunError` and `failed` state.

- [ ] **Step 5: Implement the seven stages**

Collect fetches all source inputs and optional search results. Organize deduplicates by content hash while preserving origin attempts. Map and Build invoke the model provider when configured or skip with explicit gaps when absent. Inspect runs deterministic validation. Note converts failures, uncovered jurisdictions, unsupported claims, and invalid citations into gaps and review items. Export writes `bundle.json` and `report.md`; its completion is represented in the manifest even though the bundle is the terminal artifact.

- [ ] **Step 6: Implement resume and invalidation**

Load the prior request, manifest, and checkpoints when present. Reject a reused run identifier with a different request unless `--force-stage collect` is explicit. Find the first missing, failed, skipped-but-now-configured, or fingerprint-stale stage. Invalidate it and every later stage. Completed stages with unchanged fingerprints are loaded, not executed.

- [ ] **Step 7: Run engine and concurrency tests**

Add a lock file acquired with exclusive creation. A second concurrent engine for the same run fails with `RunAlreadyActiveError`; a stale lock may be cleared only with explicit caller action. Run: `uv run pytest tests/combine -v`  
Expected: all engine tests pass.

- [ ] **Step 8: Commit COMBINE**

```bash
git add src/regulatory_harvest/combine tests/combine
git commit -m "feat: implement resumable COMBINE pipeline"
```

### Task 7: Markdown reporting, Python API, and CLI

**Files:**
- Create: `src/regulatory_harvest/analysis/report.py`
- Create: `src/regulatory_harvest/api.py`
- Create: `src/regulatory_harvest/cli.py`
- Create: `tests/analysis/test_report.py`
- Create: `tests/test_api.py`
- Create: `tests/cli/test_cli.py`

**Interfaces:**
- Consumes: `CombineEngine`, `ResearchBundle`, `validate_bundle`, and filesystem artifacts.
- Produces: `render_markdown(bundle)`, public API functions `run_research`, `validate_research_bundle`, `render_report`, and the `harvest` commands `init`, `run`, `validate`, and `report`.

- [ ] **Step 1: Write failing report and CLI tests**

```python
def test_report_surfaces_review_items_and_disclaimer(sample_bundle) -> None:
    report = render_markdown(sample_bundle)
    assert "## Attorney review required" in report
    assert sample_bundle.disclaimer in report
    assert "## Sources" in report


def test_init_writes_request_only_to_selected_directory(tmp_path: Path) -> None:
    result = cli_runner(["init", str(tmp_path)])
    assert result.returncode == 0
    assert (tmp_path / "request.json").exists()
```

- [ ] **Step 2: Run report and CLI tests to confirm failures**

Run: `uv run pytest tests/analysis/test_report.py tests/test_api.py tests/cli -v`  
Expected: collection fails because report, API, and CLI modules do not exist.

- [ ] **Step 3: Implement deterministic Markdown rendering**

Render title, scope, as-of date, executive status, jurisdiction coverage, findings, citations with source title and origin, explicit gaps, validation issues, attorney-review queue, methodology, source inventory, run metadata, and disclaimer. Escape untrusted Markdown control characters in titles and metadata. Never render secrets, raw tracebacks, or absolute local source paths; render only display names.

- [ ] **Step 4: Implement thin public API functions**

Accept `Path` or already-validated models. Return models rather than dictionaries. Keep async `run_research` and provide an explicitly named synchronous convenience wrapper `run_research_sync` that refuses to run inside an active event loop.

- [ ] **Step 5: Implement argparse CLI and exit codes**

Use exit code 0 for success, 2 for invalid input or configuration, 3 for incomplete or provider-failed runs, and 4 for invalid bundles. Every command accepts `--json` and prints exactly one JSON object to stdout in that mode. Human diagnostics go to stderr. `init` refuses to overwrite an existing request without `--force`.

- [ ] **Step 6: Run CLI tests and installed-entry-point smoke test**

Run: `uv run pytest tests/analysis/test_report.py tests/test_api.py tests/cli -v && uv run harvest --help`  
Expected: tests pass and help lists `init`, `run`, `validate`, and `report`.

- [ ] **Step 7: Commit user surfaces**

```bash
git add src/regulatory_harvest/analysis/report.py src/regulatory_harvest/api.py src/regulatory_harvest/cli.py tests/analysis/test_report.py tests/test_api.py tests/cli
git commit -m "feat: add Harvest API and local CLI"
```

### Task 8: Optional OpenAI and Tavily reference providers

**Files:**
- Create: `src/regulatory_harvest/providers/openai.py`
- Create: `src/regulatory_harvest/providers/tavily.py`
- Create: `src/regulatory_harvest/analysis/prompts/map-v1.md`
- Create: `src/regulatory_harvest/analysis/prompts/build-v1.md`
- Create: `tests/providers/test_openai.py`
- Create: `tests/providers/test_tavily.py`
- Create: `docs/providers.md`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: provider protocols and `AnalysisDraft` schemas from Task 5.
- Produces: `OpenAIModelProvider` and `TavilySearchProvider`, available through optional `openai` and `tavily` packaging extras.

- [ ] **Step 1: Write mocked provider contract tests**

Mock the OpenAI SDK response and Tavily HTTP response. Assert structured outputs parse into `AnalysisDraft`, prompt fingerprints are recorded, API keys never appear in model dumps or exceptions, 429 and 5xx errors are marked retryable, and 400-class configuration errors are not retryable.

- [ ] **Step 2: Run provider tests and confirm missing implementations**

Run: `uv run pytest tests/providers/test_openai.py tests/providers/test_tavily.py -v`  
Expected: collection fails because provider implementations do not exist.

- [ ] **Step 3: Implement the OpenAI Responses API adapter**

Load the versioned prompt files with `importlib.resources`. Send normalized source excerpts and the Pydantic JSON schema as structured output. Require `OPENAI_API_KEY` only when the adapter is instantiated without an explicit client. Record provider response ID, model, token usage, and prompt SHA-256. Do not serialize request headers or client configuration.

- [ ] **Step 4: Implement the Tavily adapter**

POST query, jurisdiction and as-of context, search depth, and result limit to the documented Tavily endpoint using httpx. Convert responses into provider-neutral `SearchResult` models. Do not automatically fetch returned URLs; Collect passes them through the safe source fetcher.

- [ ] **Step 5: Document explicit configuration and privacy behavior**

Document which source excerpts leave the local machine, how to disable both providers, environment-variable names, timeouts, and how to implement a custom provider. Include no real keys or private endpoints.

- [ ] **Step 6: Run provider tests and no-extra import test**

Run: `uv run pytest tests/providers -v && uv run python -c "import regulatory_harvest; print(regulatory_harvest.__version__)"`  
Expected: provider tests pass and the base package imports without optional provider extras.

- [ ] **Step 7: Commit reference providers**

```bash
git add pyproject.toml src/regulatory_harvest/providers src/regulatory_harvest/analysis/prompts tests/providers docs/providers.md
git commit -m "feat: add optional model and search providers"
```

### Task 9: Core documentation and end-to-end offline acceptance

**Files:**
- Create: `README.md`
- Create: `CLEAN_ROOM.md`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `THIRD_PARTY_NOTICES.md`
- Create: `examples/offline/request.json`
- Create: `examples/offline/example-rule.txt`
- Create: `examples/offline/FIXTURE_LICENSE.md`
- Create: `tests/e2e/test_offline_flow.py`

**Interfaces:**
- Consumes: the installed package and CLI from Tasks 1-8.
- Produces: reproducible offline quickstart and public clean-room contribution boundary.

- [ ] **Step 1: Write the installed offline-flow test**

Copy the example directory to a temporary location, run `harvest run --request request.json --output runs`, assert `bundle.json` and `report.md` exist, then run `harvest validate bundle.json --json` and assert exit 0 plus `"valid": true`.

- [ ] **Step 2: Run the end-to-end test and verify it fails before examples exist**

Run: `uv run pytest tests/e2e/test_offline_flow.py -v`  
Expected: test fails because the offline example does not exist.

- [ ] **Step 3: Write public documentation and synthetic fixture**

README sections: purpose, non-advice warning, installation, five-minute offline example, COMBINE, outputs, model/search providers, cite integration status, evaluation status, development, license, and limitations. CLEAN_ROOM explains prohibited inputs and release authorization. SECURITY documents safe-fetch boundaries and disclosure instructions. THIRD_PARTY_NOTICES lists direct code dependencies and the synthetic fixture's authorship.

- [ ] **Step 4: Run offline acceptance and complete core checks**

Run: `uv run pytest -q && uv run ruff check . && uv run mypy src && uv build`  
Expected: all commands exit 0 and `dist/` contains one wheel and one source distribution.

- [ ] **Step 5: Install the wheel into a clean virtual environment and execute the example**

Create a temporary virtual environment outside the repository, install the built wheel, copy `examples/offline`, run the installed `harvest` commands, and assert the installed output validates. Do not reuse the development environment for this proof.

- [ ] **Step 6: Commit core documentation and acceptance test**

```bash
git add README.md CLEAN_ROOM.md SECURITY.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md examples tests/e2e
git commit -m "docs: add offline quickstart and clean-room guidance"
```
