# Positive-credit evidence-binding remediation report

## Status

Complete. The residual finding at base commit `18b9f41` is closed with a
schema-preserving full/portable validation fix and public regression tests.
No publication, push, merge, external-service, private-evaluation, or manual
ownership/publication-authorization action was performed.

## Verified root cause

`OutOfLedgerClaim.validate_evidence_basis` and the dependency-free portable
`_validate_claim` enforced only span cardinality:

- `source_spans` required a nonempty span list; and
- `closed_universe_absence` prohibited spans.

Neither validator coupled the evidence basis to the disposition's rubric
credit. Therefore `COMPLETE` and `PARTIAL` could use
`closed_universe_absence`, survive strict response validation, persistence,
referee replacement, replay, and rebound integrity checks, and receive `1.0`
or `0.5` claim-precision credit.

The scoring contract confirmed that `COMPLETE` and `PARTIAL` are the only
positive-credit dispositions and that `UNSUPPORTED` is the zero-credit
out-of-ledger disposition for a claim unsupported by the complete supplied
record.

## Implementation

- The full `OutOfLedgerClaim` model now requires `source_spans` for
  `COMPLETE` and `PARTIAL`.
- `closed_universe_absence` is now valid only with `UNSUPPORTED`.
- Existing validation still rejects an empty `source_spans` list and an
  absence basis carrying spans.
- The portable validator mirrors the same disposition/evidence coupling and
  stable messages.
- No evaluator schema migration was introduced; evaluation schema `1.3` and
  all canonical artifact shapes remain unchanged.
- Existing full-model snapshots and portable validators are reused at grade
  response, referee replacement, resolved-grade scoring, persistence,
  deserialization, replay, and verification boundaries. Consequently the
  invariant is rechecked rather than trusted from an earlier stage.
- Exact source-record fingerprint and source-span verification remains in the
  existing full and portable evidence validators.

## TDD evidence

The regression tests were added before the production validators changed.
The final pre-production RED command covered direct full/portable validation,
both positive-credit dispositions, normal retry behavior, referee
replacement, a self-consistent rebound artifact, valid exact-span credit,
valid unsupported absence, and valid terminal-artifact parity.

Exact RED and GREEN command:

```bash
.venv/bin/pytest -q \
  tests/evaluation/test_attorney_models.py::test_positive_credit_out_of_ledger_claim_requires_source_span_basis \
  tests/evaluation/test_attorney_models.py::test_unsupported_out_of_ledger_claim_retains_absence_basis \
  tests/evaluation/test_attorney_grading.py::test_referee_replacement_cannot_introduce_positive_credit_absence_binding \
  tests/evaluation/test_attorney_grading.py::test_rebound_resolved_grade_rejects_positive_credit_absence_binding \
  tests/evaluation/test_attorney_workflow.py::test_positive_credit_absence_grade_response_uses_normal_retry_path \
  tests/evaluation/test_attorney_workflow.py::test_claim_evidence_binding_retains_expected_precision_credit \
  tests/scripts/test_attorney_eval_portable.py::test_positive_credit_absence_grade_retries_with_full_portable_parity \
  tests/scripts/test_attorney_eval_portable.py::test_portable_claim_evidence_binding_retains_expected_precision_credit \
  tests/scripts/test_attorney_eval_portable.py::test_portable_referee_replacement_cannot_introduce_positive_credit_absence \
  tests/scripts/test_attorney_eval_portable.py::test_portable_rebound_resolved_grade_rejects_positive_credit_absence \
  tests/scripts/test_attorney_eval_portable.py::test_cc0_golden_artifacts_are_byte_identical_to_core
```

Observed RED result:

```text
10 failed, 6 passed in 1.39s
```

The failures were the expected missing-invariant failures:

- direct full validation did not reject `COMPLETE` or `PARTIAL` with absence;
- full and portable workflows advanced instead of retaining the same grade
  call at attempt 2;
- referee replacements carrying the invalid combination were accepted; and
- self-consistently rebound full and portable resolved grades still scored.

The positive exact-span, unsupported-absence, and terminal parity controls
passed during RED.

After the minimal production change, the identical focused command passed:

```text
16 passed in 1.40s
```

## Verification evidence

Focused evaluator, model, grading, scoring, workflow, artifact, mutation, and
portable suites:

```text
1168 passed in 25.44s
```

Targeted Ruff and mypy on the amended production and test surface:

```text
All checks passed!
Success: no issues found in 2 source files
```

Complete public suite, captured with an explicit retained process session:

```text
1979 passed, 1 skipped in 113.88s
exit code: 0
```

The full suite was rerun once because the first tool wait detached from the
still-running pytest process before its final exit summary could be captured.
The retained-session rerun above is the completion evidence.

Extracted-package, audit, and skill-package gates:

```text
100 passed in 10.00s
```

## Reproducible build and exact-archive audit

Both universal-skill builds contained 96 files and were 353,089 bytes. They
were byte-identical:

```text
dist/regulatory-harvest-skill.zip
34e57a608781bd1adc3fd6726a47b2e9f558adce38e68aa17749c43cc7c91267

dist/regulatory-harvest-skill.repeat.zip
34e57a608781bd1adc3fd6726a47b2e9f558adce38e68aa17749c43cc7c91267
```

Both archives passed `unzip -t`. Each exact ZIP was audited separately with
the caller-supplied sealed marker file passed only as an opaque audit argument.
Both audits returned `ok: true` with `automated_findings: []`. The marker file
was not separately read, printed, copied, or embedded. Both audits retained
the expected `MANUAL_CONFIRMATION_REQUIRED` publication requirement.

## Adversarial and privacy review

The review was performed sequentially because subagent delegation was not
authorized for this task. It checked:

- `COMPLETE` and `PARTIAL` cannot use absence;
- only `UNSUPPORTED` can use absence;
- source-span and absence cardinality remain mutually exclusive;
- exact source-record fingerprints and exact spans are still verified;
- response failure follows the existing one-retry/then-inconclusive path;
- referee replacement and self-consistent retained artifacts fail closed;
- full and portable validation, retry state, scoring, and valid terminal
  artifacts retain parity;
- source-only admission, ledger-before-report isolation, anonymous candidate
  handling, referee dispute scoping, aggregate isolation, and generation
  capsule behavior are untouched; and
- the diff contains no candidate identity, private literal, sealed-marker
  value, weakened evidence check, unrelated runtime change, or schema drift.

No Critical, Important, or deferred Minor finding remains. The only retained
gate is the expected manual ownership and publication authorization decision.

## Changed files

Production:

- `src/regulatory_harvest/evaluation/attorney_models.py`
- `scripts/attorney_eval_portable.py`

Public tests:

- `tests/evaluation/test_attorney_models.py`
- `tests/evaluation/test_attorney_grading.py`
- `tests/evaluation/test_attorney_workflow.py`
- `tests/scripts/test_attorney_eval_portable.py`

Review record:

- `.superpowers/sdd/2026-08-11-automated-attorney-evaluation-skill/absence-credit-remediation-report.md`

Pre-existing modified and untracked historical documentation was preserved and
excluded from the remediation commit.

## Follow-up review round 1: exact-evidence scoring boundary

### Status and root cause

Complete. Follow-up review found that direct full and portable scoring replayed
the resolved-grade structure but did not receive the common source record.
Consequently, a structurally valid, self-consistent fabricated `source_spans`
claim could receive `COMPLETE` or `PARTIAL` precision credit without a scoring
boundary that rechecked the source-record fingerprint, source ID, offsets, and
exact quote.

This round makes the common source record a required keyword-only input to both
scorers. Full scoring canonicalizes and strictly validates the source projection;
portable scoring applies the equivalent dependency-free validation. Both bind
the sealed ledger and every out-of-ledger claim to the record fingerprint and
verify every span against exact normalized source text before calculating any
claim credit.

The immutable `report-score-inputs-<label>.json` artifact now carries the source
record. Its dedicated schema is `1.4`; other evaluation artifacts remain on
`1.3`, and the `JudgeResponse` envelope remains `1.0`. Old `1.3`/`1.2` score-input
roots and mixed nested versions fail closed. Completed-run verification also
compares the persisted source record byte-for-byte with the admission projection
before score or comparison replay. No callback or trusted boolean was added.

The independent absence invariant now enumerates every non-`UNSUPPORTED`
`CoverageDisposition`, including zero-credit dispositions, in full and portable
direct validation and rebound tests. `UNSUPPORTED` absence remains accepted and
receives zero credit.

### Round-1 TDD evidence

The new direct-scoring, exact-span mutation, referee-replacement, all-enum
absence, rebound, old-schema, and source-record-tamper tests were run before the
round-1 production change. Exact RED result:

```text
21 failed, 17 passed, 998 deselected in 0.68s
```

The failures included both scorers accepting the old no-source-record call,
rejecting the new required argument, and lacking exact source replay. The
all-enum tests also exposed that the positive-credit check ran before the
independent `UNSUPPORTED`-only invariant for `COMPLETE` and `PARTIAL`.

After implementation, the expanded focused command passed:

```text
45 passed, 1123 deselected in 1.72s
```

Broader full/portable scoring, artifact, workflow, and replay suites:

```text
341 passed in 22.61s
1326 passed in 26.97s
```

### Round-1 final verification

The first full-suite run found one clean-tracked-snapshot test fixture that
overlaid the changed artifact module but not the changed scorer. Adding the
scorer to that explicit overlay made the isolated test pass. The conclusive
full-suite rerun then completed with:

```text
2018 passed, 1 skipped in 107.12s
```

Static checks on all changed production surfaces and affected tests:

```text
All checks passed!
Success: no issues found in 5 source files
```

Extracted-package, audit, and skill-package gates:

```text
100 passed in 10.91s
```

### Round-1 reproducible build and exact-archive audit

Both builds contained 96 files, were 355,528 bytes, passed `unzip -t`, and were
byte-identical under `cmp`:

```text
dist/regulatory-harvest-skill.zip
a86e9f20c6179d5f105a8f8c12cc37a369e5e91ce94c637ddf972545f798bb9c

dist/regulatory-harvest-skill.repeat.zip
a86e9f20c6179d5f105a8f8c12cc37a369e5e91ce94c637ddf972545f798bb9c
```

Each exact ZIP was audited separately with the caller-supplied sealed marker
file passed only as an opaque argument. Both audits returned `ok: true` with
`automated_findings: []`. The marker file was not separately read, printed,
copied, or embedded. Both audits retain the expected
`MANUAL_CONFIRMATION_REQUIRED` ownership and publication-authorization gate.

No push, publish, merge, external-service call, private evaluation, or manual
authorization action was performed in round 1.

## Follow-up review round 2: portable comparison replay boundary

### Status and root cause

Complete. Although the full comparison engine already required
`candidate_inputs` and `comparator_inputs` and replayed both reports, the
portable `compare_reports` still accepted only two bare report dictionaries.
A direct caller could therefore construct internally shaped, self-fingerprinted
scores and obtain a comparative result without supplying or replaying the
schema-`1.4` immutable score inputs introduced in round 1.

Portable comparison now requires `candidate_inputs` and `comparator_inputs` as
keyword-only arguments with no fallback. For each side it:

- strictly validates the report and exact score-input artifact shape;
- requires score-input schema `1.4` and the canonical rubric;
- reconstructs the resolved grade from its original graders and referee
  decisions and requires exact equality with the persisted resolved grade;
- reruns portable `score_report` with the sealed ledger, deterministic checks,
  and common source record;
- requires the supplied report to equal the replayed report; and
- requires both reports to retain the same strict sealed-ledger and common
  source-record snapshots before selecting an outcome.

The portable aggregation workflow and completed-run verifier now pass the exact
immutable score-input dictionaries used for each report. Bare report-only calls
fail at the API boundary. No boolean, callback, optional compatibility path, or
schema change was introduced.

### Round-2 TDD evidence

The direct comparison tests were added before the portable implementation
changed. They covered the weak bare call, a rehashed fabricated report, source
fingerprint/unknown-source/bounds/quote mutations in either side's replay input,
strict shared-ledger/source-record requirements, and full/portable exact
comparison parity. Exact RED result:

```text
14 failed, 116 deselected in 0.51s
```

The bare comparison returned an outcome instead of failing, while every new
source-bearing call failed because the weak API did not accept
`candidate_inputs` or `comparator_inputs`.

After implementation, the same focused selection passed:

```text
14 passed, 116 deselected in 0.32s
```

### Round-2 final verification

Complete portable suite:

```text
130 passed in 10.21s
```

Broader full/portable scoring, artifact, workflow, comparison-replay, and
terminal-parity suites:

```text
348 passed in 22.34s
```

Conclusive complete public suite:

```text
2025 passed, 1 skipped in 114.28s
```

Targeted Ruff and mypy:

```text
All checks passed!
Success: no issues found in 1 source file
```

Extracted-package, audit, and skill-package gates:

```text
100 passed in 11.49s
```

### Round-2 reproducible build and exact-archive audit

Both builds contained 96 files, were 356,282 bytes, passed `unzip -t`, and were
byte-identical under `cmp`:

```text
dist/regulatory-harvest-skill.zip
dc2775ef4d2702f2e4e8bb9a27083977de6bcd586e999f935bde9c3f706a5ecb

dist/regulatory-harvest-skill.repeat.zip
dc2775ef4d2702f2e4e8bb9a27083977de6bcd586e999f935bde9c3f706a5ecb
```

Each exact ZIP was audited separately with the caller-supplied sealed marker
file passed only as an opaque argument. Both audits returned `ok: true` with
`automated_findings: []`. The marker file was not separately read, printed,
copied, or embedded. Both audits retain the expected
`MANUAL_CONFIRMATION_REQUIRED` ownership and publication-authorization gate.

No push, publish, merge, external-service call, private evaluation, or manual
authorization action was performed in round 2.

## Independent root verification and installed-skill forward test

The primary agent independently reran the final branch after scoped re-review:

```text
1203 focused evaluator tests passed in 24.14s
2025 full-suite tests passed, 1 skipped, in 115.58s
Ruff: All checks passed
mypy: Success on 63 source files
100 package gates passed in 11.42s
```

Two final 96-file ZIP builds were byte-identical, each passed `unzip -t`, and
each exact archive passed the sealed-marker audit with `ok:true` and no
automated finding. Their SHA-256 remained:

```text
dc2775ef4d2702f2e4e8bb9a27083977de6bcd586e999f935bde9c3f706a5ecb
```

The exact archive was atomically installed at the local Codex skill directory
and validated before replacing the prior installed copy. A scripted installed-
copy full/portable smoke produced byte-identical verified artifacts. A fresh
agent then used only the installed skill and a clean fictional packet with a
separate official status record. It completed five role calls (admission,
ledger build, ledger audit, and two independent report grades) and reached a
verified terminal result. All 17 ledger propositions received `COMPLETE`;
critical recall, weighted recall, and claim precision were each 1.0. The
deterministic score was 96.25/100, with a correctly enforced `FAIL` because the
report's limitations dimension scored 1 below the required attorney-walk floor
of 2. An independent call through the installed dependency-free entrypoint
returned `ok:true` and manifest root
`72058d543c0a290083666633d345eccf0941fc924fabfa20fe2793e743ec49ed`.

This forward result confirms that an ordinary host can complete the automated
journey without optional Python packages, browser rating, scripted answers, or
manual scoring. It also demonstrates the intended fail-closed distinction:
the earlier fixture lacking status evidence terminated `CASE_INVALID`, while
the complete status packet was admitted and scored. Qualified-attorney review
and the manual ownership/publication gate remain mandatory.
