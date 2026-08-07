# Release checklist

This checklist separates reproducible technical evidence from decisions that software cannot make. A technically complete local build is not authorization to publish.

## Automated gates

Run every command from the candidate commit with no unstaged or uncommitted release changes:

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run mypy src
uv run pytest -q
uv build
uv run python scripts/audit_release.py --json
```

The release audit examines the exact path set reported by `git ls-files`, skips binary and non-UTF-8 content, and returns exit code `1` when it finds an automated issue. JSON output contains finding codes, paths, line numbers, and generic messages; it never includes matched values.

| Code | Release concern |
| --- | --- |
| `SECRET_PATTERN` | A tracked value resembles a credential or private key. |
| `PRIVATE_NETWORK_URL` | A tracked URL addresses a private or non-global host. |
| `ABSOLUTE_HOME_PATH` | A tracked absolute path identifies a user's home directory. |
| `LEGACY_INTERNAL_IDENTIFIER` | A prohibited legacy or private project identifier remains. |
| `N8N_WORKFLOW_EXPORT` | JSON resembles an exported n8n workflow. |
| `UNLICENSED_FIXTURE` | A fixture has no nearby provenance and license manifest. |
| `GENERATED_EXPORT` | A run or output directory contains a generated research artifact. |

The scanner has a small path, finding-code, and exact-value allowlist for synthetic security tests and one public design example. An additional match in an allowlisted file still fails. Every exception must be reviewed as carefully as a new dependency. The audit supplements—not replaces—history review, dependency review, secret-scanning services, and human inspection.

Before declaring the candidate technically verified:

1. Install the built wheel in a new environment outside the checkout.
2. Run the offline example using the installed `harvest` command.
3. Validate and render the produced evidence bundle.
4. Run the synthetic LegalBench-RAG evaluation.
5. Record commands, versions, results, and artifact hashes under `docs/verification/`.
6. Confirm the distribution does not contain generated bundles, private documents, upstream benchmark data, or development-only files.

## Manual ownership and publication gate

The audit always reports `MANUAL_CONFIRMATION_REQUIRED`, even when all automated checks pass. Before anyone creates a public remote, pushes this history to a public service, publishes a package, or announces a release, the repository owner must independently confirm:

1. they own or have permission to publish every contribution;
2. employment, contractor, confidentiality, invention-assignment, and client obligations permit publication;
3. third-party code, data, fixtures, names, and marks have been reviewed and attributed correctly;
4. no client, matter, personal, employer, or private operational information appears in the files or Git history;
5. the security contact and supported-version policy are ready for public use; and
6. they affirmatively authorize the chosen repository and package publication.

Record that decision outside this codebase in an access-controlled location with the approver, date, candidate commit, and publication destinations. Do not encode approval as a file or boolean that an automated check could mistake for authority.

Until that confirmation is complete, a local version may be described as technically verified, but it must not be described as publicly released.
