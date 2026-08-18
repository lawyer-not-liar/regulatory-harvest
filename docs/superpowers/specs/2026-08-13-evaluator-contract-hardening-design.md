# Evaluator Contract Hardening Design

**Date:** 2026-08-13
**Status:** Approved for implementation

## Goal

Make the fully automated attorney evaluation reliable enough to reach report
grading on deep matters without weakening its sealed-ledger, source-parity,
currentness, or fail-closed guarantees.

This remediation addresses the three stopping conditions in the verified
`20260813T213413Z-remediated-build-2c7f9fa-v1` private run:

1. initial ledger-audit findings were rejected unless they were already encoded
   as complete executable ledger transactions;
2. a semantically coherent partial-coverage grade was rejected by a narrower
   finding-code rule; and
3. the India current-law packet stopped at admission because it did not contain
   official status or version evidence through the declared as-of date.

## Root causes

### Initial audit and unresolved-dispute semantics were conflated

The initial source-only auditor has one job: identify every material omission,
overaggregation, unsupported proposition, relationship defect, or materiality
problem in the proposed ledger. The current validator also requires every audit
finding to carry the complete replacement entries needed to execute `add`,
`edit`, `split`, or `merge` immediately.

That duplicates the repair role and scales poorly. In the France matter, the
auditor found broad, precise omissions across a 46-entry ledger, but did not
rebuild dozens of exact replacement entries inside the audit response. The
audit was therefore rejected before the repair role could do the rebuilding.

### The exception finding code excluded valid partial coverage

`MATERIAL_EXCEPTION_MISSING` was valid only when the whole sealed exception
entry was graded `MISSING`. A report can accurately cover part of a multi-part
exception while omitting a material condition. `PARTIAL` plus that finding code
is the correct representation for that circumstance.

### Submission was the first deterministic semantic check

The runner validates a response only when `eval-submit` mutates the run. A
failed response consumes the first of two bounded attempts. The retry receives
the same packet, so hidden semantic constraints are likely to fail twice. The
runner needs a read-only preflight that uses the exact submission validator
without creating response, diagnostics, call, or manifest artifacts.

## Approved architecture

### 1. Two audit validation levels

Keep the existing JSON wire shape. Change only how it is validated at each
phase.

The initial `audit_ledger` response is a complete collection of source-only
audit findings. Each finding must have a unique identifier, a permitted action
classification, materiality, and a concrete rationale. Target identifiers and
proposed entries remain available, but a finding does not need to duplicate the
repair role by carrying a transaction-ready replacement.

The `repair_ledger.remaining_audit` response remains strict. Every unresolved
finding must have an executable action payload because the deterministic
sealer or one dispute-scoped referee must be able to resolve it. No qualitative
finding may pass from repair into sealing.

The public core and standard-library portable engine will expose separate
validation functions for these two levels. Run verification will replay the
initial audit with finding-level validation and the remaining audit with strict
transaction validation.

This preserves the security property that only a fully validated repaired
ledger can be sealed. It removes redundant reconstruction work from the
auditor.

### 2. Explicit response contracts in role packets

The source-only audit packet will carry a small deterministic
`audit_action_contract` that explains the permitted initial finding shape and
the stricter remaining-audit transaction shapes. The repair instructions will
state that all initial findings must be resolved and any remaining finding must
be transaction-ready.

The grade packet will carry a deterministic `finding_code_contract` listing the
allowed disposition and ledger-context predicates for each entry and narrative
finding code. This is instruction metadata derived from the frozen rubric and
sealed ledger contract, not additional legal evidence.

### 3. Read-only `eval-preflight`

Add this command to the full and portable runners:

```text
eval-preflight --run RUN --response RESPONSE
```

It reads and verifies the immutable run, loads the one pending request,
validates the canonical response envelope and request binding, and executes the
same role-specific transition validation used by `eval-submit`. It discards the
calculated transition and writes nothing.

The canonical success result is:

```json
{"issues":[],"ok":true,"operation":"grade_report","request_fingerprint":"<sha256>","schema_version":"1.0"}
```

An invalid role response returns `ok:false`, exit code `2`, and one or more
stable issue objects. It does not consume a judge attempt. Integrity failures
remain exit code `5`.

The skill workflow must run preflight before every `eval-submit`, revise the
response internally until preflight passes, and submit only the validated
response. The attorney never sees or operates this loop.

### 4. Correct exception-code semantics

Permit `MATERIAL_EXCEPTION_MISSING` when all of these are true:

- the sealed entry category is `exception`;
- its materiality is `material` or `critical`; and
- the grade disposition is `MISSING` or `PARTIAL`.

All other finding-code predicates remain unchanged. Duplicate codes and codes
outside their declared contexts still fail closed.

### 5. India currentness evidence stays private

Research official Indian sources for the DPDP Act and Rules status through
2026-07-17. Retain the exact official source bytes, canonical URL, retrieval
date, language, and status relationship only in the access-controlled private
evaluation workspace. Do not add legal source packets, candidate reports,
baseline mappings, or evaluation outputs to the open-source repository or ZIP.

The refreshed case must be new and sealed. The terminal prior run remains
immutable.

## Testing strategy

Use synthetic public fixtures only in repository tests.

- Prove a complete initial audit with precise non-transaction findings advances
  to repair in both engines.
- Prove the same non-transaction finding is rejected in `remaining_audit`.
- Prove `PARTIAL` plus `MATERIAL_EXCEPTION_MISSING` is accepted only for a
  material or critical exception.
- Prove role packets contain byte-equivalent response contracts in the full and
  portable engines.
- Prove valid and invalid `eval-preflight` results match across engines and do
  not change any run bytes or manifest state.
- Preserve golden full/portable artifacts, terminal exit codes, capsule parity,
  and tamper detection.

## Release and evaluation boundary

Build one reproducible universal skill ZIP, audit it for private material,
stage it in a temporary directory, and replace only the installed local
`regulatory-harvest` skill with a recoverable backup. Then generate and verify
fresh candidate capsules and run a new sealed three-case comparison suite.

Do not publish, push, open a pull request, alter the prior baseline, or reuse a
terminal evaluation run.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
