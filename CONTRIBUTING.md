# Contributing

Regulatory Harvest is not accepting external contributions, pull requests, or
feature requests during the experimental beta. The repository is public so
people can inspect, install, and evaluate the software—not as an invitation to
contribute changes at this stage.

Unsolicited pull requests may be closed without review. GitHub Issues and
Projects are disabled. Security vulnerabilities should be reported through the
private process in [SECURITY.md](SECURITY.md), not through a public issue or
pull request.

The project may open to outside contributions later. This file will be updated
if that policy changes.

## Maintainer development notes

Maintainers must read `CLEAN_ROOM.md`, use only synthetic or clearly
redistributable fixtures, and preserve the project's deterministic validation,
privacy, and provenance boundaries.

## Development setup

```bash
python -m pip install uv
uv sync --frozen --all-extras --dev
```

Use test-driven development for behavior changes. The test must fail for the intended reason before production code is added. Prefer real components and temporary directories; mock only an external or slow boundary.

Run before merging:

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
