# Provision Coverage Closure Design

**Date:** 2026-08-14
**Status:** Approved for implementation planning

## Goal

Make material omission control a persisted, deterministic delivery gate without
changing the attorney-facing report structure. Regulatory Harvest must still
produce a readable, regulation-centered attorney briefing, but a newly prepared
matter cannot complete until every authoritative source unit and every detected
provision lead has been expressly accounted for.

The coverage control is generation-side and source-derived. It must remain
independent from the sealed attorney evaluator, comparator reports, private
benchmark ledgers, and storage systems.

## Problem

The current workflow has two different notions of coverage:

1. The drafting instructions tell the host to create a proposition coverage
   table before writing prose.
2. The deterministic engine persists provision leads and blocks only a capped
   priority subset, currently at most three leads per topic.

The proposition table is not part of `analysis-draft.json`, so finalization
cannot verify that it existed, that it covered the complete authority, or that
its material propositions reached the report. Nonpriority leads are recorded as
informational and can be omitted without blocking completion. A draft can
therefore be precise about the propositions it states while remaining materially
incomplete.

Prompt-only reinforcement cannot close this gap. The missing control is a
versioned transaction between the complete source, the host's proposition map,
the exact evidence layer, and the visible attorney brief.

## Design principles

1. **Source-derived, not benchmark-derived.** Coverage targets come only from
   the prepared source dossier. The generation workflow must not read evaluator
   ledgers, grades, comparator reports, mappings, or prior evaluation responses.
2. **Fail closed for new matters.** Every required source unit and every
   detected lead must receive a valid disposition before finalization can report
   completion.
3. **Legal judgment stays with the host.** Deterministic code identifies text
   that must be reviewed and validates relationships. It does not decide what a
   statute means or whether a proposition is legally material.
4. **Exact evidence remains authoritative.** A covered proposition is valid only
   when its source-supported claims resolve to exact source text.
5. **Coverage must reach the attorney.** A proposition is not covered merely
   because it exists in an internal finding. Its claims must appear in a visible
   legal-analysis unit in the attorney brief or be represented as a bounded gap.
6. **No attorney workflow tax.** The provision map and repair loop are internal
   skill work. The user still supplies a question and sources and receives the
   same report, audit, and validation receipt.
7. **Portable parity.** The full Python runtime and dependency-free portable
   runtime must produce the same identifiers, diagnostics, canonical artifacts,
   and completion decision.

## Considered approaches

### Prompt-only expansion

Strengthen the existing drafting prompt and rely on the model to maintain its
own working table. This is the smallest change, but it preserves the present
failure mode: the table is neither observable nor enforceable. Rejected.

### Make every heuristic lead blocking

Remove the per-topic cap and require a claim or disposition for every current
keyword lead. This is easy to explain and improves English-language recall, but
it remains dependent on a narrow vocabulary. It also treats repeated keywords
as the source boundary and does not reliably cover foreign-language provisions,
numbered clauses without a matched keyword, or operative conditions separated
from the matched sentence. Rejected as the sole control.

### Structural source units plus proposition coverage ledger

Create language-agnostic structural source units, retain all current heuristic
leads, and require the host to reconcile both through a persisted proposition
coverage ledger. This adds internal work, but it directly addresses the observed
omission mechanism while preserving exact-evidence and report-quality controls.
Selected.

## Architecture

The design adds four bounded components to the existing prepare/draft/finalize
flow.

### 1. Structural source-unit inventory

`prepare` creates deterministic source units from every successfully normalized
source that is not explicitly marked `commentary_analysis` or `unusable`.
Secondary and unknown-quality sources remain covered unless explicitly excluded;
the system must not silently assume that unknown material is disposable.

A source unit is a small, exact, structurally bounded portion of the normalized
text. Boundaries use, in descending preference:

- provision headings and their clauses;
- numbered, lettered, or otherwise enumerated paragraphs and list items;
- paragraph boundaries;
- sentence and semicolon-level clause boundaries, including common Unicode legal
  punctuation; and
- bounded subdivisions for any unusually large remaining clause.

The segmenter is language-agnostic at its coverage boundary. Recognized legal
headings and English-language signals may enrich metadata, but their absence
cannot prevent text from becoming a required source unit. For every eligible
source, the units form a nonoverlapping source-order partition in which every
non-whitespace character belongs to exactly one unit. Empty whitespace may be
excluded. Navigation text, repeated boilerplate, and unfamiliar formatting are
still emitted and must be expressly dispositioned; the segmenter cannot discard
them through a relevance heuristic.

Each unit records:

```json
{
  "unit_id": "unit_...",
  "source_id": "src_...",
  "start_char": 120,
  "end_char": 286,
  "heading": "Article 24",
  "locator": "Article 24(2)",
  "excerpt": "...",
  "coverage_required": true
}
```

`unit_id` is a stable digest of the source identifier, exact offsets, and exact
excerpt. The excerpt must equal
`normalized_text[start_char:end_char]`. Units are emitted in source order with
stable canonical ordering.

The dossier gains a versioned object:

```json
{
  "coverage_contract_version": "proposition-coverage-v1",
  "source_unit_inventory": {
    "inventory_version": "source-units-v1",
    "unit_count": 42,
    "required_unit_count": 42,
    "units": []
  }
}
```

The existing `evidence_inventory` remains an independent heuristic index. Its
priority cap may remain useful for ordering work, but priority no longer controls
whether a detected lead must be dispositioned under the new contract.

### 2. Persisted proposition coverage ledger

`analysis-draft.json` gains `coverage_contract_version` and a
`proposition_coverage` array. A row represents one independently operative legal
proposition or one explicit decision that the referenced source material is a
gap or not material to the question.

```json
{
  "coverage_id": "coverage-operator-register",
  "unit_ids": ["unit_..."],
  "lead_ids": ["lead_..."],
  "category": "requirements",
  "proposition_type": "duty",
  "disposition": "covered",
  "elements": {
    "subject": {"status": "stated", "text": "covered operator"},
    "operative_rule": {"status": "stated", "text": "must maintain a register"},
    "object": {"status": "stated", "text": "processing activities"},
    "trigger_or_threshold": {"status": "not_applicable", "text": null},
    "conditions_or_exceptions": {"status": "stated", "text": "subject to ..."},
    "timing": {"status": "not_established", "text": null},
    "consequence_or_remedy": {"status": "not_applicable", "text": null},
    "authority_or_route": {"status": "not_applicable", "text": null}
  },
  "claim_ids": ["claim-register"],
  "gap_codes": ["REGISTER_TIMING_NOT_ESTABLISHED"],
  "rationale": null
}
```

The controlled proposition types are:

- `status`;
- `definition`;
- `scope`;
- `right`;
- `duty`;
- `prohibition`;
- `exception`;
- `deadline`;
- `enforcement_trigger`;
- `enforcement_route`;
- `remedy`;
- `penalty`;
- `appeal`;
- `implementation`;
- `other`.

For a `covered` row, `elements` contains all eight named semantic elements. Each
element has one of three statuses:

- `stated`, which requires nonblank text;
- `not_applicable`, which requires `text: null`; or
- `not_established`, which requires `text: null` and a matching authored gap for
  a covered or gap disposition.

For `covered`, `subject` and `operative_rule` must be `stated`. If any other
element is `not_established`, the row must name a matching authored gap. If no
element is `not_established`, `gap_codes` must be empty. The element statuses
force the host to consider the qualifications most often lost through
compression without asking deterministic code to invent or interpret them.

The row dispositions are:

- `covered`: requires the complete element map and at least one exact
  source-supported `claim_id`; it may carry `gap_codes` only for elements marked
  `not_established`;
- `gap`: requires one or more matching `gap_codes` and a concrete rationale,
  cannot carry claims, and may omit `elements`; if elements are present, none
  may be `stated`; or
- `not_material`: requires a concrete rationale and cannot carry elements,
  claims, or gaps.

Every row must reference at least one prepared target across `unit_ids` and
`lead_ids`; either array may otherwise be empty. This permits a lead emitted from
commentary-only material to receive a disposition even though that source does
not produce required structural units.

Rows may reference multiple units when a proposition depends on a cross-reference
or a multi-clause rule. A unit or lead may appear in multiple rows when one
clause states several distinct propositions. This is necessary for definitions,
enumerated duties, exception chains, and trigger/consequence pairs.

### 3. Deterministic coverage reconciliation

Finalization reconciles the source-unit inventory, complete lead inventory,
coverage rows, built findings, exact citations, authored gaps, and brief bindings.
For a `proposition-coverage-v1` matter, all of the following are blocking:

1. Every `coverage_required` unit appears in at least one coverage row.
2. Every detected provision lead appears in at least one coverage row.
3. Every referenced unit and lead exists in the prepared dossier.
4. Each covered row references existing `source_supported` claims.
5. The exact resolved citations for those claims overlap every unit and lead
   assigned to that covered row. A citation in a neighboring clause does not
   satisfy the target.
6. A lead assigned to a covered or gap row uses a compatible issue category.
7. Every covered row's claims appear in a visible `legal_analysis` paragraph,
   list item, or table row in the attorney brief.
8. Every `not_established` element and every `gap` disposition names an authored
   gap whose category and source identifiers match the referenced targets.
9. `not_material` rows contain no claims or gaps and preserve their rationale in
   the internal artifact.
10. Coverage identifiers are unique and all output ordering and hashes are
    canonical.

The validator checks structure, identity, exact evidence, and referential
closure. It does not judge whether a host's proposition text is a correct legal
interpretation or whether a `not_material` rationale is substantively persuasive.
Those remain attorney-review and evaluation questions.

The principal diagnostics are:

- `COVERAGE_TARGET_UNRESOLVED`;
- `COVERAGE_TARGET_UNKNOWN`;
- `COVERAGE_ROW_INVALID`;
- `COVERAGE_CLAIM_UNKNOWN`;
- `COVERAGE_CLAIM_NOT_SOURCE_SUPPORTED`;
- `COVERAGE_EVIDENCE_OUTSIDE_TARGET`;
- `COVERAGE_CLAIM_NOT_VISIBLE`;
- `COVERAGE_GAP_INVALID`; and
- `COVERAGE_ELEMENT_INCOMPLETE`.

Diagnostics identify only prepared source, unit, lead, coverage, claim, and gap
identifiers. They must not expose local source paths or private evaluator state.

### 4. Coverage artifact and automatic repair loop

Finalization writes `coverage-review.json` schema version `2.0`. It contains:

- contract and inventory versions;
- counts by disposition, category, proposition type, and element status;
- a deterministic result for every source unit, provision lead, and coverage
  row;
- unresolved identifiers and bounded diagnostics; and
- a canonical `coverage_review_hash`.

The validation receipt adds `proposition_coverage_valid`. For a new-contract
matter, `provision_recall_valid` is the conjunction of legacy lead-recall safety
checks and proposition-coverage validity. `status: completed` requires:

- deterministic bundle validation;
- zero blocking exact-evidence review items;
- `proposition_coverage_valid: true`; and
- `provision_recall_valid: true`.

An invalid coverage review returns the existing review-required exit behavior
and preserves enough internal diagnostics for repair. The skill must repair the
draft and rerun finalization without asking the attorney to operate the ledger.
It may still render a provisional report and audit to aid repair, but it cannot
describe the matter as completed.

## Attorney-facing report behavior

The report schema, canonical anchors, and narrative style do not change.
Regulatory Harvest continues to produce:

1. Executive Summary;
2. the adaptive regulation-centered legal walk;
3. Key Requirements;
4. Penalties and Enforcement; and
5. Implementation Workplan.

The coverage ledger is not rendered as a database table in the report. Its
effect should be richer and better-qualified legal analysis: actors, triggers,
thresholds, conditions, exceptions, timing, enforcing authority, remedies, and
penalties survive compression into the narrative. The Implementation Workplan
remains separate from the law's requirements.

`audit.md` may summarize coverage counts and point to the private internal
coverage artifact, but it must not expose raw model reasoning or an evaluator
answer key.

## Compatibility and migration

- Existing completed bundles and evaluation histories remain byte-verifiable.
- Matters prepared without `coverage_contract_version` retain the current
  provision-lead behavior.
- Newly prepared matters declare `proposition-coverage-v1` and require the new
  ledger. An old-format draft used with a new matter fails with bounded repair
  diagnostics rather than silently falling back.
- `lead_reviews` remains parseable during migration. It may continue to satisfy
  legacy matters, but it cannot substitute for the new ledger.
- Full and portable parsers accept the same new fields and reject the same
  malformed relationships.
- The skill package, template, schema reference, prompt, package manifest, and
  installation artifact are updated together.
- No storage backend, MCP server, n8n workflow, or database dependency is added.

## Error handling and safety

- Malformed inventory or coverage data fails closed as review-required or
  invalid input; it never degrades to advisory coverage.
- Unknown identifiers, missing exact quotes, ambiguous quotes, invalid gap
  bindings, and invisible covered claims are blocking.
- A failed or unusable source is represented through the existing source gap
  controls; no source units are fabricated for unavailable text.
- Commentary-only material may remain outside required source units, but any
  heuristic lead actually emitted from it must still receive a disposition.
- Currentness remains an epistemic statement about retained authority and the
  as-of date. The coverage ledger cannot convert an unverified status into an
  operative-law conclusion.
- The exact attorney-review disclaimer remains unchanged.

## Testing strategy

### Unit and model tests

- Source units are deterministic, stable, exact source slices, and ordered.
- Structural units are produced for numbered or paragraph-level foreign-language
  text without relying on English keywords.
- Long clauses, adjacent clauses, repeated boilerplate, CRLF-normalized input,
  and duplicate headings do not create unstable or overlapping identities.
- Coverage-element status/value combinations and disposition cardinalities are
  strict.

### Adversarial reconciliation tests

- Omitting a nonpriority duty blocks completion.
- A citation to one duty cannot satisfy an adjacent duty.
- A requirement without its material exception or threshold remains uncovered.
- A penalty consequence cannot silently cover its separate trigger or enforcing
  route.
- A deadline, appeal route, defense, or defined category cannot disappear merely
  because no English signal matched it.
- A finding that exists internally but is absent from the visible brief blocks
  completion.
- A generic category gap cannot satisfy responsive source text without a valid
  target-specific coverage row.
- Valid multi-unit propositions, explicit nonmaterial decisions, and bounded
  gaps complete successfully.

### Runtime, packaging, and regression tests

- Full and portable prepare/finalize paths emit byte-identical inventories,
  coverage reviews, receipt fields, diagnostics, and hashes.
- CLI, package, clean-install, and skill-instruction tests require the new
  contract.
- Existing terminal matters and sealed evaluator replay verification remain
  unchanged.
- Ruff, mypy, privacy scans, package validation, and the full test suite remain
  green.

## Locked-suite acceptance gate

After public-safe implementation and local verification, rebuild and install the
skill locally, then rerun the same locked private three-case comparison suite.
The rerun must use:

- the same captured public source packets;
- fresh Regulatory Harvest generation;
- the same sealed comparator reports;
- fresh isolated evaluator roles;
- no evaluator ledger, grade, mapping, or prior response as generation input;
  and
- the existing terminal integrity and replay checks.

The iteration is successful only if:

1. Regulatory Harvest receives an absolute `PASS` on all three cases, not merely
   a higher relative score.
2. Deterministic exact-evidence precision remains valid with no unsupported
   source claim introduced.
3. Every new matter completes with both `proposition_coverage_valid` and
   `provision_recall_valid` true.
4. The regulation-centered structure, Key Requirements boundary, Penalties and
   Enforcement treatment, and narrative legal walk do not regress.
5. Capsule verification and terminal replay remain valid.

If any case fails, the implementation is not represented as having met the
quality gate. The failure clusters may guide another generic source-side design
iteration, but private evaluator answers must never be copied into public code,
tests, prompts, or fixtures.

## Privacy and release boundary

Public changes contain only generic deterministic logic, synthetic fixtures, and
public-safe documentation. The repository must not receive private source
packets, comparator reports, evaluation ledgers, mappings, scores, reviewer
responses, client facts, local absolute paths, or answer keys. The locked suite
and its receipts remain in the private local workspace.

No publication, push, pull request, or public release is part of this design
without separate user authorization.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
