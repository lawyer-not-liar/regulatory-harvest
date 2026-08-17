# Final whole-branch review fix report

## Status

Complete. All seven findings in `final-review-findings.md` were fixed in one
TDD-driven implementation wave on `codex/universal-skill`. No publication,
push, merge, external service, private evaluation content, or manual
ownership/publication authorization action was performed.

## Finding resolution

### 1. Source-sufficient grading and dispute-scoped refereeing

- Full and portable grade packets now include the complete common
  closed-universe source record in addition to the sealed ledger, derived
  source spans, anonymous report, deterministic checks, and rubric.
- Schema-1.3 entry and narrative grades bind exact report passages.
- Schema-1.3 out-of-ledger claims bind the common source-record fingerprint
  and either exact verified source spans or an explicit
  `closed_universe_absence` basis.
- Accepted, persisted, replayed, repaired, and referee-replaced grades are
  revalidated against the exact anonymous report and source bytes.
- Report-referee packets are reconstructed exactly during artifact
  verification. They are label-free and dispute-scoped, and contain only the
  exact disputed anonymous passages, relevant ledger or rubric context,
  common source record, relevant source spans, both alternatives and
  rationales, and explicit meanings for each allowed resolution.
- Referee packets do not contain candidate identifiers, anonymous labels, the
  other report, other graders, or unrelated disputes.
- Full and portable request schemas, packet bytes, artifact bytes, repair
  paths, referee paths, evidence failures, and replay/tamper behavior have
  direct parity coverage.

### 2. Exact generation-instruction parity

- Formal two-capsule comparisons now require exact equality of the captured
  generation-instruction string before run-directory creation or judging.
- Full and portable initialization return the same stable
  `EVALUATION_SOURCE_PARITY_UNPROVEN` failure when two otherwise valid
  capsules differ only in their generation instructions.
- The evaluation guide and reference now state this formal-comparison
  boundary.

### 3. Explicit current and historical bundle hash contracts

- Newly written research bundles use schema `1.1`; their hash covers every
  current field.
- The verifier recognizes both genuinely persisted schema-`1.0` field shapes:
  the initial public-release shape and the later expanded 1.0 shape. It uses
  Pydantic's preserved nested field-presence metadata to select the exact
  historical projection.
- Original nondefault 1.0 fields, including `source_mode`, `publisher`,
  `effective_date`, and `supersession`, remain inside the historical hash.
- Mixed historical shapes and nondefault post-1.0 fields declared as 1.0 fail
  closed with `BUNDLE_SCHEMA_CONTENT_INVALID`; historical tampering continues
  to produce `BUNDLE_HASH_MISMATCH`.
- `migrate_bundle_hash_contract` first verifies the retained source-schema
  hash, then returns a copied schema-1.1 bundle with a current-contract hash.
- Old/new, both historical shapes, migration, tamper, mixed-shape,
  mixed-version, post-1.0 downgrade, and evaluator-native control tests are
  present.

### 4. Duplicate JSON member rejection

- Repository and exact-archive JSON decoding now uses a duplicate-detecting
  object-pairs hook.
- Any repeated object member produces the generic `DUPLICATE_JSON_KEY`
  finding before last-value decoding can erase a populated credential.
- Diagnostics do not print member names, values, or private markers.

### 5. Windows-unsafe ZIP member rejection

- Exact-archive validation rejects any colon-bearing segment, including
  alternate-data-stream forms.
- Reserved device detection normalizes all superscript 1/2/3 aliases before
  checking `COM` and `LPT` names.
- Existing traversal, absolute/drive path, separator, trailing-dot/space,
  control/format character, duplicate, case-collision, and Unicode
  normalization-collision defenses remain covered.

### 6. Conservative aggregate judge isolation

- Evaluation result schema 1.3 now requires aggregate `judge_isolation`.
- Any relevant completed or failed `sequential_same_context` call makes the
  aggregate `sequential_same_context`; otherwise it is `fresh_context`.
- The current response is included before terminal result construction, and
  retry/failure provenance is retained in the aggregation.
- Immutable verification recomputes the aggregate from every nonpending
  manifest call and rejects a rebound result/report/hash with weaker
  provenance.
- The delivered Markdown report discloses the aggregate while the manifest
  retains detailed per-call provenance. Full and portable output parity is
  tested.

### 7. CI audits the exact universal ZIP

- CI now passes `dist/regulatory-harvest-skill.zip` to the public audit
  immediately after building it.
- The owner-controlled external-marker audit and manual publication
  authorization remain separate from CI.

## Schema and migration decisions

- Evaluation artifacts: `1.2` to `1.3`. Retained 1.2 and older evaluation
  roots are explicitly unsupported rather than reinterpreted. The host-facing
  `JudgeResponse` envelope remains `1.0`.
- Research bundles: new writers emit `1.1`. Both authentic persisted 1.0
  shapes verify under their exact historical projections. A verified 1.0
  bundle can be copied and rehashed through
  `migrate_bundle_hash_contract`; mixed or post-1.0 downgrade shapes are not
  migrated.

## TDD evidence

The adversarial tests were introduced before the corresponding production
changes. The observed RED behavior was:

- a two-valid-capsule instruction mismatch initialized successfully instead
  of returning source-parity failure;
- graders lacked the full source record, evidence-free or fabricated
  out-of-ledger bindings could not be rejected consistently, dispute packets
  lacked exact passages/context/source evidence, and aggregate isolation was
  absent from delivered and replay-verified artifacts;
- authentic historical schema-1.0 hashes failed after model defaults were
  added; the first attempted projection also exposed both real schema-1.0
  shapes, with the initial public-release shape producing
  `BUNDLE_HASH_MISMATCH` and the expanded shape initially producing
  `BUNDLE_SCHEMA_CONTENT_INVALID`;
- populated credentials followed by empty duplicate JSON members were erased
  by last-value decoding;
- colon/ADS and superscript `COM`/`LPT` archive names were accepted; and
- the CI assertion failed because the audit command did not name the built
  ZIP.

The final GREEN evidence is:

```text
Focused evaluator/artifact/full-portable/bundle/audit/build/package wave
1465 passed in 72.66s

Portable evaluator
97 passed in 10.93s

Final bundle hash-contract suite after both historical-shape fixes
84 passed in 0.16s

Final full public suite after the last production change
1964 passed, 1 skipped in 120.55s

Extracted-package, audit, and skill-package gates
100 passed in 12.21s

Ruff
All checks passed!

mypy
Success: no issues found in 66 source files
```

## Reproducible build and exact-artifact audit

Both builds contained 96 files and were 352,920 bytes. They were byte-identical:

```text
dist/regulatory-harvest-skill.zip
299f784e7ab446d22e7f749de814204b5c884de27f6fe40629bb7dee7e9b5836

dist/regulatory-harvest-skill.repeat.zip
299f784e7ab446d22e7f749de814204b5c884de27f6fe40629bb7dee7e9b5836
```

Each exact ZIP was audited separately with the caller-supplied sealed marker
file passed only as an opaque audit argument. Both audits returned `ok: true`
with `automated_findings: []`. The marker file was not separately read,
printed, copied, or embedded. Both audits retained the expected
`MANUAL_CONFIRMATION_REQUIRED` publication requirement.

## Changed files

Release, documentation, and workflow:

- `.github/workflows/ci.yml`
- `README.md`
- `docs/evaluation.md`
- `references/attorney-evaluation.md`

Full and portable runtime:

- `scripts/attorney_eval_portable.py`
- `scripts/audit_release.py`
- `scripts/harvest_portable.py`
- `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- `src/regulatory_harvest/evaluation/attorney_models.py`
- `src/regulatory_harvest/evaluation/attorney_workflow.py`
- `src/regulatory_harvest/models/bundle.py`
- `src/regulatory_harvest/storage/__init__.py`
- `src/regulatory_harvest/storage/serialization.py`
- `src/regulatory_harvest/validation/bundle.py`

Tests and public synthetic fixture:

- `tests/cli/test_eval_cli.py`
- `tests/evaluation/test_attorney_artifacts.py`
- `tests/evaluation/test_attorney_grading.py`
- `tests/evaluation/test_attorney_models.py`
- `tests/evaluation/test_attorney_mutations.py`
- `tests/evaluation/test_attorney_scoring.py`
- `tests/evaluation/test_attorney_workflow.py`
- `tests/fixtures/attorney-eval/responses/scripted-responses.json`
- `tests/scripts/test_attorney_eval_portable.py`
- `tests/scripts/test_audit_release.py`
- `tests/scripts/test_build_skill.py`
- `tests/scripts/test_evaluation_capsule_provenance.py`
- `tests/scripts/test_harvest_skill.py`
- `tests/validation/test_bundle.py`

Review record:

- `.superpowers/sdd/2026-08-11-automated-attorney-evaluation-skill/final-review-fix-report.md`

## Self-review and concerns

- An independent read-only whole-diff review found and then verified fixes for
  both authentic schema-1.0 shapes. Its final result was no remaining blocker
  across all seven findings, full/portable parity, referee noninterference,
  evidence replay/tamper validation, and conservative isolation provenance.
- Exact-diff review found no candidate-identity or anonymous-label disclosure
  in referee packets and no downgrade fallback that silently ignores new
  content.
- Both sealed-marker exact-archive audits found no private literal.
- Pre-existing unrelated modified and untracked historical plan,
  specification, and verification files were preserved and excluded from the
  scoped commit.
- The manual ownership and publication-authorization gate remains
  intentionally unresolved. No release action was taken.
