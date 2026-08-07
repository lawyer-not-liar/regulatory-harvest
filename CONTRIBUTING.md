# Contributing

Thank you for improving Regulatory Harvest. This project is evidence-sensitive and clean-room by design, so provenance and failure behavior matter as much as happy-path features.

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Before changing code

1. Read `CLEAN_ROOM.md` and confirm that every input to the contribution is permitted.
2. Open or reference a focused issue for changes to the bundle schema, COMBINE semantics, security boundary, provider behavior, or legal-research claims.
3. Keep core packages independent from optional providers, cite/OpenContracts, LegalBench-RAG, servers, databases, and vector stores.
4. Use synthetic or clearly redistributable fixtures and record their provenance.

## Development setup

```bash
python -m pip install uv
uv sync --frozen --all-extras --dev
```

Use test-driven development for behavior changes. The test must fail for the intended reason before production code is added. Prefer real components and temporary directories; mock only an external or slow boundary.

Run before submitting:

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
```

Changes to source intake, serialization, citation offsets, resume behavior, provider redaction, or adapter mappings need focused negative tests. Do not weaken deterministic validation to accommodate model output.

## Public contract changes

The JSON bundle is versioned. A breaking schema or semantic change requires a design note, migration approach, updated fixtures, and an intentional schema-version decision. Model confidence can never override a deterministic citation failure.

Provider adapters must expose safe, stable configuration fingerprints that include behavior-affecting settings and exclude secrets. Provider exceptions must be converted to credential-safe errors before they reach persisted state or CLI output.

## Documentation and commits

- Explain limitations and uncertainty directly.
- Do not describe synthetic fixtures as law.
- Add dependency or data notices when applicable.
- Keep commits focused and preserve provenance-related corrections.
- Never include keys, private endpoints, client names, matter identifiers, or confidential examples.

By contributing, you represent that you have the right to submit the contribution under the project license.
