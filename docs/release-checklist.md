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
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
python3 /path/to/skill-creator/scripts/quick_validate.py .
skills-ref validate .
uv run python scripts/audit_release.py --repo . \
  --archive dist/regulatory-harvest-skill.zip \
  --private-markers /path/to/local-private-evaluation-markers.txt \
  --json
```

The release audit examines tracked and unignored candidate files plus the exact built ZIP, skips binary and non-UTF-8 content, and returns exit code `1` when it finds an automated issue. Keep the optional newline-delimited private marker file outside the repository; it supplies private round IDs, record IDs or hashes, and report-only phrases without committing them. JSON output contains finding codes, paths, line numbers, and generic messages; it never includes matched values.

| Code | Release concern |
| --- | --- |
| `SECRET_PATTERN` | A tracked value resembles a credential or private key. |
| `PRIVATE_NETWORK_URL` | A tracked URL addresses a private or non-global host. |
| `ABSOLUTE_HOME_PATH` | A tracked absolute path identifies a user's home directory. |
| `LEGACY_INTERNAL_IDENTIFIER` | A prohibited legacy or private project identifier remains. |
| `N8N_WORKFLOW_EXPORT` | JSON resembles an exported n8n workflow. |
| `UNLICENSED_FIXTURE` | A fixture has no nearby provenance and license manifest. |
| `GENERATED_EXPORT` | A run or output directory contains a generated research artifact. |
| `PRIVATE_EVALUATION_MARKER` | Content contains a private evaluation field or matches a locally supplied private marker. |

The scanner has a small path, finding-code, and exact-value allowlist for synthetic security tests and one public design example. An additional match in an allowlisted file still fails. Every exception must be reviewed as carefully as a new dependency. The audit supplements—not replaces—history review, dependency review, secret-scanning services, and human inspection.

Before declaring the candidate technically verified:

1. Build the universal skill ZIP twice from the same clean committed snapshot and confirm identical file counts, byte lengths, and SHA-256 hashes.
2. Confirm both archives and both clean extractions have one `regulatory-harvest/` root and contain `SKILL.md`, the runtime engine, runner, assets, references, license, notices, README, and package metadata. In particular, require the qualification module and template plus the full and portable evaluator and skill runners.
3. Confirm the skill name matches the archive root and the description remains at or below Claude Desktop's 200-character limit.
4. Confirm the archive excludes Git state, worktrees, tests, internal plans, caches, generated matters, prior distributions, and private records.
5. Extract the ZIP into a clean directory and run `prepare` and `finalize` in both source modes with site packages disabled and package-index access blocked, without importing the development checkout.
6. Confirm the extracted flow produces a substantive profiled report with the three canonical anchors and adaptive matter-specific sections, a separate evidence audit, `coverage-review.json`, exact resolved citations, a sealed valid bundle, and no stale no-provider gap.
7. Confirm every V2 source unit has all nine dimension dispositions, every lead has a disposition, independently operative rules are distinct scalar atoms, material qualifications use valid typed relationships, and genuine source-tied gaps remain gaps. Confirm exact evidence covers assigned targets, relationships cover both endpoint source contexts, and critical or material atoms and relationships have visible natural-prose bindings without rendered internal IDs.
8. Confirm the validation receipt separately reports `evidence_precision_valid`, `proposition_coverage_valid`, and `provision_recall_valid` as true. Any unresolved unit, lead, atom, relationship, evidence, gap, or visible-binding diagnostic must block completion.
9. From the clean extracted ZIP, run `--help` for `eval-submit-safe` and all five `eval-qualify-*` commands on the full runtime and under isolated Python with site packages disabled on the portable runtime. Then run all five `eval-gen-*` commands, a terminal source qualification, and a terminal one-report `eval-*` journey. Confirm the full and portable runtimes produce byte-identical public requests, diagnostics, results, artifacts, and roots for the same inputs.
10. Run the mutation suite for collapsed independent duties, misclassified exceptions, adjacent-but-outside deadline evidence, penalties missing their trigger, one-endpoint relationship visibility, one-source cross-source relationships, duplicate/cyclic/unknown relationship IDs, malformed typed and raw fields, V1 replay drift, input mutation, and full/portable byte divergence. Confirm each mutation produces its locked issue codes and disposition.
11. Confirm evaluation role packets are self-contained, blind where required, and sufficient for a fresh host context to return schema-valid responses without undocumented protocol knowledge.
12. Confirm one external report yields an absolute result with `comparison: null`; two external reports or a mixed external/capsule pair cannot be represented as a formal build comparison.
13. Confirm the generation capsule actually invokes or loads the exact digest-verified runnable build it records. Merely hashing an unused archive is not a build evaluation.
14. Review `references/security-and-privacy.md`; confirm the evaluation directory is access-controlled, non-public, and non-synced, and that no secrets, environment files, configuration, Git state, or unrelated records were captured.
15. Upload that exact ZIP to Claude Desktop with code execution enabled and exercise both source modes.
16. Install the same folder or ZIP in Codex and exercise both source modes.
17. Install the built wheel in a new environment outside the checkout and run the offline CLI example.
18. Run the synthetic LegalBench-RAG evaluation.
19. Keep all private evaluation packets, prior analyses, reviewer responses, comparison results, and the local private-marker file outside the release candidate.
20. Record commands, versions, results, and artifact hashes under `docs/verification/` without converting unperformed UI checks into claims.
21. Adversarially confirm that diagnostics cannot echo exception or source text; qualification cannot admit missing currentness evidence; failed guarded submission cannot write any byte; repair instructions cannot permit a fourth attempt; qualification replay rejects changed artifacts; and the archive contains no private marker or identifying absolute path.
22. Treat qualification `ADMITTED` only as source-record readiness. It is not a report `PASS`, and neither automated result authorizes publication or delivery of legal advice.

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
