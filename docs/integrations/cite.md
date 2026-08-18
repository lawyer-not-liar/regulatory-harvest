# cite integration

Regulatory Harvest can exchange evidence with [cite, currently distributed from the OpenContracts repository](https://github.com/Open-Source-Legal/OpenContracts), without importing or depending on cite's Django implementation. The integration is optional and uses public external interfaces only.

cite is useful as a collaborative citation graph and persistent review environment. It is not required to run Harvest, and Harvest remains responsible only for its portable local artifacts.

## Supported surfaces

The adapter discovers capabilities on the configured instance in this order:

1. `/.well-known/mcp.json`, followed by MCP `tools/list` on the advertised same-origin endpoint;
2. `/llms.txt` for documented tool names; and
3. GraphQL schema introspection at `/graphql` for supported mutations.

Reads use cite's streamable HTTP MCP server. The adapter currently calls `list_documents`, `get_document_text`, `list_annotations`, and `list_relationships`. Writes use the GraphQL `addAnnotation` and `addRelationship` mutations. A discovered MCP URL on another origin is rejected so the configured bearer token cannot be redirected to another host.

The client caches capabilities for its lifetime, uses a ten-second default timeout, limits response and assembled-document sizes, and suppresses remote bodies from errors.

## Install and credentials

The cite adapter uses Harvest's base HTTP stack and requires no optional
package extra:

```bash
python -m pip install regulatory-harvest
```

Set a bearer token in an environment variable. Do not put a token in shell arguments, request files, target maps, or receipts.

```bash
export CITE_TOKEN="..."
```

Public MCP reads can run without a token. Use `--require-auth` for a private import; this makes a missing token a local error instead of silently receiving only public records. Exports always require a token.

## Import

The import command takes a cite corpus **slug**:

```bash
harvest cite import \
  --url https://cite.example \
  --corpus public-corpus \
  --output exchanges/public-corpus \
  --json
```

For a private corpus:

```bash
harvest cite import \
  --url https://cite.example \
  --corpus private-corpus \
  --output exchanges/private-corpus \
  --require-auth \
  --token-env CITE_TOKEN
```

The command writes `cite-import.json` atomically beneath the selected output directory. It preserves cite corpus, document, and annotation identifiers; normalizes returned extracted text as UTF-8 text; hashes that normalized text; and re-resolves every annotation quotation. cite offsets are never trusted after normalization. Missing text becomes a failed source plus an explicit gap. Missing, whitespace-only, or ambiguous quotation matches become review items rather than fabricated citations.

Documents with identical content remain separate sources when their cite origins differ. Duplicate pages for the same cite document or annotation identifier are ignored with warnings.

## Export

Export requires GraphQL node IDs that the MCP summaries do not expose. Supply a local target map from each Harvest source ID to its cite document node ID and zero-indexed page:

```json
{
  "source-1": {
    "document_id": "RG9jdW1lbnRUeXBlOjEyMw==",
    "page": 0
  }
}
```

The export `--corpus` value, annotation label, relationship label, and document targets are GraphQL IDs, not MCP slugs:

```bash
harvest cite export \
  --url https://cite.example \
  --corpus Q29ycHVzVHlwZTox \
  --bundle runs/example/bundle.json \
  --document-targets cite-targets.json \
  --annotation-label-id QW5ub3RhdGlvbkxhYmVsVHlwZTox \
  --relationship-label-id QW5ub3RhdGlvbkxhYmVsVHlwZToy \
  --output exchanges/example \
  --json
```

Harvest verifies the terminal bundle hash and validates the complete evidence graph before capability discovery or writes. A deterministic plan creates one evidence annotation per citation, one claim annotation per claim/citation pair, and optional claim-to-evidence relationships. Annotation long descriptions carry the Harvest run and record identifiers. Unsupported relationship writes and missing document targets are reported explicitly.

The initial adapter supplies the selected quotation and a valid empty-token annotation structure. It does not translate Harvest character offsets into cite PDF token coordinates, so exported records may participate in the citation graph without rendering a precise PDF highlight. A later coordinate adapter can add that behavior without changing the Harvest bundle schema.

Writes are sequential by default. `--concurrency` may be set from 1 through 5. Successful, reused, failed, and skipped writes are preserved in `cite-export.json`; successful writes are not rolled back after a later failure.

## Retries and idempotency

cite's MCP annotation listing does not expose Harvest provenance metadata, so remote-only duplicate detection is not reliable. Keep the local receipt and pass it on a retry:

```bash
harvest cite export \
  ... \
  --previous-receipt exchanges/example/cite-export.json
```

Each plan item has a Harvest idempotency key and content fingerprint. A prior remote ID is reused only when the corpus, key, and fingerprint all match. Changed content with a reused Harvest identifier is written again rather than being mistaken for the old record. Receipts contain no bearer token or remote error body.

## Compatibility and permissions

- Missing required annotation-write capability stops export before writes.
- Missing optional relationship capability creates an explicit skipped record.
- cite permission filtering can make private documents, text, or annotations unavailable; Harvest records those effects as gaps.
- GraphQL mutations can still be rejected by cite's authorization or rate limits after discovery. The receipt remains retryable.
- Import and export use different cite identifiers: MCP slugs for import, GraphQL node IDs for export.

For an opt-in, read-only live smoke test, set `HARVEST_LIVE_CITE_URL`, `HARVEST_LIVE_CITE_CORPUS`, and, when required, `HARVEST_LIVE_CITE_TOKEN`, then run:

```bash
uv run pytest -m live tests/adapters/cite/test_live.py -v
```

The test discovers capabilities and lists at most one document; it performs no mutations and records no response body. Never enable live tests in untrusted pull requests, and never record live responses as fixtures. Repository fixtures are synthetic and sanitized.

## Clean-room and license boundary

This adapter was implemented against cite's public discovery, MCP, and GraphQL contracts. It imports no cite code, models, services, or database schema and redistributes no cite documents or annotations. cite/OpenContracts is MIT-licensed; use of a hosted instance and its content remains subject to the operator's terms and the permissions attached to that content.
