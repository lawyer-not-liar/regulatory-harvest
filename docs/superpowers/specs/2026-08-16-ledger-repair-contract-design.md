# Ledger Repair Contract Design

**Date:** 2026-08-16
**Status:** Approved for implementation planning

## Context

The designated publication evaluation stopped correctly after two fresh
`repair_ledger` responses reached the same public-safe semantic diagnostic.
Independent review verified that the controller remained fail-closed, refused
responses were never committed, and qualification and generation replay stayed
valid. The immediate failures were response-construction failures, not a
demonstrated storage, transition, or validator-integrity defect.

The repair request currently tells a fresh evaluator to satisfy "every ledger
invariant," but it does not carry the closed invariant checklist already stated
in the ledger-build request. JSON Schema constrains individual fields but cannot
express the cross-entry, exact-source, and category-dependent rules enforced by
`validate_ledger`. A genuinely fresh repair role therefore receives less useful
contract information than the initial builder even though repair is the more
complex operation.

## Goal

Make the source-only ledger contract explicit and identical across
`build_ledger`, `audit_ledger`, and `repair_ledger`, while distinguishing rules
the controller enforces deterministically from actions a fresh evaluator must
attest it performed. This lets a fresh evaluator construct a validator-compliant
repair without weakening validation, revealing rejected response details, or
changing retry limits.

## Non-goals

- Do not relax, bypass, or infer around any existing ledger invariant.
- Do not expose private source text, candidate reports, mappings, scores, or
  response-specific validator details in public-safe diagnostics.
- Do not change the maximum-attempt, repeated-diagnostic, fresh-context, or
  fail-closed rules.
- Do not resume or mutate the stopped evaluation cycle.
- Do not broaden the work into grading, qualification, generation, or report
  authoring behavior.

## Chosen approach

Create one deterministic `ledger_invariant_contract` projection and include it
in every full and portable ledger request. The request instructions will point
to that object and summarize its required use. This is stronger than repeating
prompt prose alone because the contract is versioned, machine-readable,
byte-comparable, and testable, while remaining source-only and candidate-free.

The contract has this canonical logical shape:

```json
{
  "schema_version": "1.1",
  "binding": {
    "case_fingerprint": "source_record.source_record_fingerprint"
  },
  "identity": {
    "ledger_ids": "unique",
    "gap_ids": "unique",
    "entry_gap_ids": "disjoint",
    "walk_order": "unique_contiguous_zero_based"
  },
  "relationships": {
    "targets": "known_ledger_ids",
    "self_reference": "forbidden",
    "trigger_link_categories": ["enforcement", "penalty"],
    "trigger_target_categories": ["requirement", "prohibition"]
  },
  "citations": {
    "source_ids": "known_retained_sources",
    "slices": "unique_exact_half_open",
    "quote": "exact_source_text",
    "operative_categories_require_exact_support": true,
    "operative_categories_forbid_commentary_only_support": true
  },
  "required_fields": {
    "requirement_prohibition_right": ["actor", "object"],
    "deadline": ["timing"],
    "exception": ["conditions_or_exceptions"],
    "enforcement": ["enforcing_authority", "enforcement_route", "trigger_link"],
    "penalty": ["consequence", "trigger_link"],
    "remedy": ["consequence"]
  },
  "materiality_rationale": {
    "minimum_word_tokens": 5,
    "forbidden_exact_normalized_values": [
      "critical",
      "high priority",
      "important",
      "material",
      "significant"
    ]
  },
  "repair_closure": {
    "resolve_every_initial_finding": "evaluator_attestation",
    "remaining_audit_request_fingerprint": "deterministically_enforced",
    "complete_true_requires_full_recheck": "evaluator_attestation",
    "remaining_disputes": "deterministically_enforced_transaction_ready_only"
  }
}
```

The implementation must derive the projection from one full-runtime helper and
mirror the exact canonical value in the stdlib-only portable runtime. The value
must never describe an evaluator attestation as a deterministically verified
fact. Tests, not duplicated explanatory prose, lock full/portable equivalence.

## Request flow

1. `build_ledger` receives the source record and the invariant contract. Its
   instructions require a complete ledger satisfying that contract.
2. `audit_ledger` receives the source record, proposed ledger, audit-action
   contract, and the same invariant contract. Its instructions require checking
   every listed invariant and producing all initial findings.
3. `repair_ledger` receives those inputs plus the audit and the same invariant
   contract. Its instructions require applying every audit transaction,
   globally renumbering walk order, resolving all new and changed relationship
   targets, rechecking exact citations, and returning a complete ledger plus a
   bound remaining audit.
4. The controller continues to validate with the existing schema and semantic
   code before any write. The invariant projection is explanatory input; it is
   never an alternate validator or authority.

Adding the payload field changes request fingerprints by design. Historical
runs remain immutable and replay under their existing bytes. A run must use one
contract generation consistently across build, audit, and repair: absent for
pre-contract runs, exact `1.0` for the first contract generation, or exact `1.1`
for the corrected mixed deterministic/attested contract. Only newly initialized
runs use `1.1`.

## Error and privacy behavior

Rejected responses retain the existing stable public-safe diagnostic bucket.
The controller must not return response-specific invariant failures to a fresh
repair role. Refusal atomicity, attempt counting, repeated-code stopping, and
sealed artifact behavior remain byte-for-byte compatible except for new request
bytes and fingerprints.

The invariant contract contains only generic public evaluator rules. It must
contain no case facts, source excerpts, candidate labels, report passages,
scores, mappings, local private paths, or owner identifiers.

## Verification

Tests must prove all of the following:

- Full and portable invariant-contract values and ledger-request bytes match.
- All three ledger operations include the same exact contract once.
- The stopped-cycle failure shape is represented by a fictional public-safe
  fixture containing adds, edits, a split, new identifiers, relationship
  remapping, exact citations, and final contiguous walk order.
- A correct repaired response passes guarded submission and advances; malformed
  relationship, walk-order, citation, category-field, materiality, and audit-
  binding variants remain write-free refusals.
- Existing refusal codes, retry ceilings, legacy replay, and no-mutation
  controls remain unchanged.
- Full test, Ruff, mypy, package manifest, isolated portable help, reproducible
  archive, and privacy audit gates pass.

## Release qualification

After implementation and independent review, build the exact commit twice and
require byte-identical archives. Install recoverably, initialize fresh schema-
1.1 source-only qualification capsules, and requalify the frozen source sets.
Then run exactly one fresh designated evaluation cycle against the newly bound
commit, archive, installed bytes, qualification roots, and approved comparator.

The designated cycle runs once and determines what may be claimed, not whether
technically verified public code may exist as an experimental beta:

- a verified absolute PASS meeting every approved threshold permits a beta with
  the positive internal-validation result;
- a substantive FAIL blocks publication until the quality failure is fixed;
- a mechanical or inconclusive stop may permit an explicitly experimental beta
  only if every deterministic public gate passes, the incomplete evaluation is
  disclosed, and no performance or benchmark claim is made.

No additional case, replacement candidate, or second cycle is permitted before
the publication decision. A push, PR, release, or visibility change still
requires the final external-publication action to be explicitly confirmed at
handoff.

## Rejected approaches

### Prompt-only duplication

Repeating the build prompt in the repair prompt is smaller, but it remains
unversioned prose and is easier for full and portable runtimes to drift.

### Detailed rejection feedback

Returning response-specific validator findings could improve repair success,
but it changes the privacy and isolation boundary, encourages feedback-driven
overfitting, and is unnecessary when the stable invariant contract is supplied
up front.
