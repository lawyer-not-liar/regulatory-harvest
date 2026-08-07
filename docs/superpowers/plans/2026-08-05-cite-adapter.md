# Regulatory Harvest cite Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional cite/OpenContracts adapter that exchanges source documents, annotations, citations, and findings through documented external surfaces without coupling Harvest core to cite's Django implementation.

**Architecture:** A small asynchronous client performs capability discovery and typed GraphQL, REST, or MCP requests. Pure mapping functions translate remote payloads to and from canonical Harvest models. Contract tests use sanitized recorded responses; live tests remain opt-in.

**Tech Stack:** Python 3.11+, httpx, Pydantic 2, pytest, pytest-asyncio, and respx.

## Global Constraints

- Core modules must not import cite/OpenContracts code or require cite dependencies.
- Use documented public APIs; do not import cite's Django models or internal services.
- Preserve Harvest and cite identifiers together as provenance.
- Never record credentials or unsanitized private document text in test fixtures.
- Capability failure must be actionable and must not silently omit requested imports or exports.
- Adapter installation is optional through the `cite` packaging extra.

---

### Task 1: Capability-aware cite client

**Files:**
- Create: `src/regulatory_harvest/adapters/__init__.py`
- Create: `src/regulatory_harvest/adapters/cite/__init__.py`
- Create: `src/regulatory_harvest/adapters/cite/models.py`
- Create: `src/regulatory_harvest/adapters/cite/client.py`
- Create: `tests/adapters/cite/test_client.py`
- Create: `tests/adapters/cite/fixtures/capabilities.json`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: httpx and configured cite base URL/token.
- Produces: `CiteCapabilities`, `CiteClient.discover_capabilities()`, `list_documents`, `get_document`, `list_annotations`, `create_annotation`, and `create_relationship`.

- [ ] **Step 1: Write failing discovery and redaction tests**

```python
@pytest.mark.asyncio
async def test_discovery_detects_supported_operations(cite_client) -> None:
    capabilities = await cite_client.discover_capabilities()
    assert capabilities.can_read_documents is True
    assert capabilities.can_write_annotations is True


def test_client_repr_redacts_token() -> None:
    client = CiteClient("https://cite.example", token="secret-value")
    assert "secret-value" not in repr(client)
```

- [ ] **Step 2: Run client tests and verify missing adapter**

Run: `uv run pytest tests/adapters/cite/test_client.py -v`  
Expected: collection fails because the cite adapter does not exist.

- [ ] **Step 3: Implement explicit capability discovery**

Probe `/.well-known/mcp.json`, `/llms.txt`, and configured GraphQL metadata in that order, recording which documented operations are available. Time out after ten seconds. Cache capabilities for the client lifetime. Raise `CiteCompatibilityError` naming missing operations before performing an import or export.

- [ ] **Step 4: Implement typed request handling**

Use bearer authentication only when explicitly configured. Set a project user agent, bounded timeouts, response-size limits, and safe error messages. Parse response data into adapter Pydantic models with `extra="allow"` only at the remote boundary; convert to strict core models afterward.

- [ ] **Step 5: Run client tests and commit**

Run: `uv run pytest tests/adapters/cite/test_client.py -v && uv run ruff check src/regulatory_harvest/adapters/cite tests/adapters/cite`  
Expected: all commands exit 0.

```bash
git add pyproject.toml src/regulatory_harvest/adapters tests/adapters/cite
git commit -m "feat: add capability-aware cite client"
```

### Task 2: Import cite documents and annotations

**Files:**
- Create: `src/regulatory_harvest/adapters/cite/importer.py`
- Create: `tests/adapters/cite/test_importer.py`
- Create: `tests/adapters/cite/fixtures/document.json`
- Create: `tests/adapters/cite/fixtures/annotations.json`

**Interfaces:**
- Consumes: `CiteClient`, remote documents and annotations.
- Produces: `import_cite_corpus(client, corpus_id) -> CiteImportResult` containing `SourceRecord` and `CitationSpan` objects plus warnings.

- [ ] **Step 1: Write failing import mapping tests**

Assert document text becomes normalized source text, cite document IDs are retained in `external_ids`, annotation spans become exact Harvest offsets, permission-filtered or missing documents produce explicit warnings, and annotations whose quote does not match the returned text become invalid review items.

- [ ] **Step 2: Run importer tests and verify failure**

Run: `uv run pytest tests/adapters/cite/test_importer.py -v`  
Expected: collection fails because `importer.py` does not exist.

- [ ] **Step 3: Implement pure mapping functions**

Separate network pagination from `map_cite_document` and `map_cite_annotation`. Preserve source URL, title, content hash, media type, citation metadata, cite corpus/document/annotation identifiers, and retrieved timestamp. Re-resolve the quote against normalized Harvest text; never trust remote offsets after normalization.

- [ ] **Step 4: Test pagination, duplicates, and unavailable text**

Deduplicate documents by cite identifier, retain multiple origins when content hashes match, and record a gap when an annotation references text the caller cannot retrieve.

- [ ] **Step 5: Run tests and commit import path**

Run: `uv run pytest tests/adapters/cite/test_importer.py -v`  
Expected: all importer tests pass.

```bash
git add src/regulatory_harvest/adapters/cite/importer.py tests/adapters/cite
git commit -m "feat: import cite evidence into Harvest bundles"
```

### Task 3: Export findings and citations to cite

**Files:**
- Create: `src/regulatory_harvest/adapters/cite/exporter.py`
- Create: `tests/adapters/cite/test_exporter.py`
- Create: `tests/adapters/cite/fixtures/export-responses.json`

**Interfaces:**
- Consumes: a validated `ResearchBundle`, `CiteClient`, and target corpus identifier.
- Produces: `export_bundle_to_cite(client, corpus_id, bundle) -> CiteExportResult`.

- [ ] **Step 1: Write failing export-plan tests**

Assert invalid bundles are rejected before network access, source spans map to cite annotations, findings map to relationships or metadata only when supported by capabilities, every outbound record includes Harvest provenance, and a retry does not duplicate records carrying the same Harvest identifier.

- [ ] **Step 2: Run exporter tests and verify failure**

Run: `uv run pytest tests/adapters/cite/test_exporter.py -v`  
Expected: collection fails because `exporter.py` does not exist.

- [ ] **Step 3: Implement deterministic export planning**

Build a pure `CiteExportPlan` before performing writes. Include source document lookups, annotation creates, relationship creates, and skipped unsupported operations. Use Harvest IDs as idempotency/provenance keys. Refuse to export error-level-invalid citations.

- [ ] **Step 4: Implement bounded writes and partial-failure reporting**

Execute plan entries sequentially by default with configurable concurrency no greater than five. Return created, reused, skipped, and failed entries. Do not roll back successful remote writes, but preserve a complete retryable result artifact.

- [ ] **Step 5: Run export tests and commit**

Run: `uv run pytest tests/adapters/cite/test_exporter.py -v`  
Expected: all exporter tests pass.

```bash
git add src/regulatory_harvest/adapters/cite/exporter.py tests/adapters/cite
git commit -m "feat: export Harvest findings to cite"
```

### Task 4: cite CLI, docs, and contract verification

**Files:**
- Create: `src/regulatory_harvest/adapters/cite/cli.py`
- Create: `docs/integrations/cite.md`
- Create: `tests/cli/test_cite_cli.py`
- Create: `tests/adapters/cite/test_contract.py`
- Modify: `src/regulatory_harvest/cli.py`
- Modify: `THIRD_PARTY_NOTICES.md`

**Interfaces:**
- Consumes: client, importer, exporter, and base CLI.
- Produces: `harvest cite import`, `harvest cite export`, and documented compatibility behavior.

- [ ] **Step 1: Write failing CLI tests**

Test missing extra, missing URL, absent credentials for a private target, incompatible capabilities, successful JSON status, sanitized errors, and export refusal for an invalid bundle.

- [ ] **Step 2: Run CLI tests and verify failures**

Run: `uv run pytest tests/cli/test_cite_cli.py -v`  
Expected: cite subcommands are absent.

- [ ] **Step 3: Register lazy cite subcommands**

Import the optional adapter only after `cite` is selected. Include target URL and corpus identifier, never token, in JSON status. Store import/export receipts beneath the caller-selected run directory.

- [ ] **Step 4: Write integration documentation**

Document supported surfaces, token handling, import/export field mapping, idempotency, capability errors, permission effects, sanitized fixture policy, and opt-in live-test environment variables.

- [ ] **Step 5: Run adapter contract and full regression tests**

Run: `uv run pytest tests/adapters/cite tests/cli/test_cite_cli.py -v && uv run pytest -q`  
Expected: all tests pass without a running cite instance.

- [ ] **Step 6: Commit cite user surfaces**

```bash
git add src/regulatory_harvest/cli.py src/regulatory_harvest/adapters/cite/cli.py docs/integrations/cite.md tests/cli/test_cite_cli.py tests/adapters/cite/test_contract.py THIRD_PARTY_NOTICES.md
git commit -m "docs: add cite integration workflow"
```
