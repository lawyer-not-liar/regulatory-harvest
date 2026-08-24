# Evaluator Protocol 2.2 Recoverable Compilation Design

**Author:** Earl Mah
**Created:** 2026-08-19
**Last updated:** 2026-08-19
**Status:** Approved for implementation planning
**Supersedes for new runs after approval and readiness:** Protocol 2.1 control flow
**Compatibility:** Protocols 1.3, 2.0, and 2.1 remain replay-only

## Context

Protocol 2.1 moved most controller-owned work out of evaluator roles and split
source-referee and grading responses into bounded fragments. Its public test,
parity, replay, package, and audit gates passed. One authorized private readiness
cycle then reached the first source-review call and stopped before substantive
evaluation:

- generation completed and passed every deterministic generation gate;
- the source-review role produced an initial response and one fresh repair;
- both responses were refused write-free as `MECHANICAL_RESPONSE_INVALID`;
- no evaluator response was accepted;
- source audit, source referee, and grading never ran; and
- the verified run ended `INCONCLUSIVE_MECHANICAL` without a result artifact.

This outcome does not show that the report was legally correct, incorrect, or
unassessable. It shows that an internal handoff between components we control did
not satisfy a strict representation contract. Protocol 2.1 incorrectly allowed
that interface failure to become an evaluation-ending state.

The strict boundary is still necessary. Accepted artifacts must remain canonical,
request-bound, source-grounded, replayable, and tamper-evident. The defect is where
strictness is applied and what happens when an internal draft does not compile.

Protocol 2.2 separates evaluator-authored semantic drafts from controller-authored
canonical responses. Internal draft failures are recoverable work-state failures.
They never become a substantive evaluation disposition, never consume a
substantive repair budget, and never invalidate the candidate analysis.

## User-visible requirement

An internally generated evaluator handoff must satisfy this invariant:

> It either compiles deterministically into the exact strict response required by
> the pending request, or the same fragment remains pending and can be resumed.
> Failure to compile is an engine condition, not an evaluation result.

The system must continue evaluating once that fragment compiles. It must not skip
the fragment, invent missing substance, weaken source validation, or silently
accept malformed artifacts.

## Goals

- Preserve strict canonical accepted artifacts and exact full/portable replay.
- Make the controller, not the model, own response envelopes, identifiers,
  ordering, fingerprints, canonical serialization, and aggregate construction.
- Give internal evaluator adapters a smaller semantic draft contract than the
  strict persisted response contract.
- Fragment source review and source audit so one malformed item cannot discard an
  entire large review.
- Automatically normalize only mechanically equivalent representations.
- Reissue only the exact affected fragment when substantive clarification is
  required.
- Leave an exact pending request in place when bounded automatic recovery is
  exhausted.
- Resume the same run from the same pending request after interruption, provider
  failure, or a compatible engine correction.
- Preserve every previously accepted fragment byte-for-byte across pause and
  resume.
- Distinguish internal compilation failure, external invalid submission, integrity
  failure, and substantive uncertainty in APIs, diagnostics, metrics, and docs.
- Demonstrate zero evaluation-ending internal mechanical failures in the public
  stress gate before another private readiness run.

## Non-goals

- Do not make every model output acceptable.
- Do not infer legal substance from malformed or ambiguous draft fields.
- Do not repair meaning-changing contradictions with heuristics.
- Do not weaken exact source or report-passage validation.
- Do not weaken case, request, report, grader-lane, dispute, batch, artifact,
  manifest, path, symlink, hash, inventory, or replay binding.
- Do not expose rejected draft content to a repair role.
- Do not let a reviewer see auditor or referee output.
- Do not skip an uncompiled fragment to reach later phases.
- Do not treat an engine pause as substantive `INCONCLUSIVE`.
- Do not upgrade or rewrite a Protocol 1.3, 2.0, or 2.1 run in place.
- Do not promise that low-quality but schema-valid legal analysis is mechanically
  improved. Independent audit and adjudication remain responsible for substance.
- Do not authorize another private cycle or publication action through this
  design alone.

## Considered approaches

### Relax the persisted response validators

This would reduce refusals quickly, but it would mix tolerance into the trusted
artifact boundary. It could admit unbound evidence, unknown fields, cross-case
data, ambiguous quotations, or noncanonical results. Replay would become harder
to reason about and full/portable drift would become more likely.

This approach is rejected.

### Keep the strict schema and return better errors

Specific diagnostics would improve debugging, but a large all-or-nothing source
review could still fail after substantial useful work. A second invalid attempt
would still either stop the evaluation or invite an unbounded retry loop.

This is useful as part of the solution but is insufficient by itself.

### Compile bounded semantic drafts and preserve the pending fragment

The evaluator role authors only bounded semantic judgments. A deterministic
compiler normalizes mechanically equivalent forms, resolves controller-owned
references, constructs the strict response, and submits only that compiled
response. If compilation needs clarification, only the same fragment is reissued.
If the bounded driver budget is exhausted, the driver pauses while the immutable
run retains the exact pending request.

This is the selected approach.

## Architectural decision

Protocol 2.2 introduces a two-boundary evaluator pipeline:

```text
exact pending request
    -> internal evaluator role
    -> bounded semantic draft
    -> deterministic draft compiler
       -> safe normalization
       -> exact evidence resolution
       -> strict semantic validation
       -> controller-owned response envelope
    -> existing strict preflight
    -> atomic accepted-response commit
    -> next exact pending request

draft cannot compile
    -> no accepted-response write
    -> same request remains pending
    -> bounded fresh reissue of only that fragment
    -> if still blocked, driver exits ENGINE_PAUSED
    -> later resume reads and reissues the same pending request
```

The strict preflight and replay verifier remain the final authority. The draft
compiler is not an alternate acceptance path. It is the only internal producer of
the strict response that preflight accepts.

## Trust boundaries

### Internal evaluator path

The built-in evaluator adapter is trusted to supply provider, model, isolation,
and request context to the controller. It receives an exact pending request and
asks the model for an operation-specific inner draft. It never asks the model to
author:

- protocol or schema version;
- operation name;
- request or case fingerprint;
- provider or model identity;
- isolation metadata;
- call, proposal, dispute, requirement, batch, finding, or artifact identifiers;
- response or aggregate fingerprints;
- artifact paths;
- manifest fields; or
- canonical JSON bytes.

The adapter must use provider-native schema-constrained output when the provider
supports it. A fallback parser may locate one bounded JSON object, but it may not
guess missing legal substance or combine multiple conflicting objects.

### External strict-submission path

`eval-submit-safe` continues to accept only a complete strict Protocol 2.2
response bound to the current request. An invalid external submission is refused
write-free. Repeated external invalid submissions do not terminalize the run. The
caller may correct and resubmit while the same request remains pending.

There is no public command that bypasses the strict response boundary by writing a
draft directly into the run.

## Draft and compiled-response contracts

Each operation has two models:

- `*DraftV22` contains only bounded evaluator-authored semantic fields.
- `*ResponsePayloadV22` is the strict controller-compiled persisted payload.

The draft models may admit a narrow set of representational variations that the
compiler can resolve without changing meaning. The compiled models remain strict,
closed, immutable, and canonical.

The compiler returns one of three typed outcomes:

- `Compiled`: one strict response ready for ordinary preflight;
- `NeedsClarification`: safe reason codes for reissuing the same fragment; or
- `EngineDefect`: the compiler or adapter failed to honor its own invariant.

No compiler outcome is an evaluation disposition.

## Safe deterministic normalization

The compiler may perform only transformations whose semantic equivalence is
mechanically demonstrable:

- trim leading and trailing prose whitespace only outside evidence-quotation
  fields;
- canonicalize object-key order and JSON separators;
- map enum text by an explicit versioned case-folded alias table with exactly one
  target;
- assign every controller-owned identifier and fingerprint;
- resolve an exact source or report quotation as written;
- replace a whitespace-normalized quotation with the unique exact source span
  only when exactly one span matches, without case-folding, punctuation changes,
  or Unicode-content normalization;
- convert a controller-issued local ordinal into its canonical reference;
- remove byte-identical duplicate items while retaining first occurrence order.

The compiler must return `NeedsClarification` instead of guessing when:

- a required substantive field is absent;
- an enum has zero or multiple allowed interpretations;
- a quotation has zero or multiple permitted matches;
- a source, proposal, requirement, dispute, batch, report, or dependency reference
  cannot be uniquely resolved from the pending request;
- two nonidentical items claim the same local identity;
- a dependency target is ambiguous;
- a required rationale or finding is substantively empty; or
- draft content exceeds the five-item fragment limit.

## Content quality is not a mechanical gate

A draft may be incomplete, unpersuasive, conservative, aggressive, or legally
wrong while still being mechanically interpretable and grounded in permitted
evidence. The compiler must not reject it merely because another evaluator might
disagree with its substance.

Once the controller can uniquely interpret every required field, bind every cited
passage, and construct the strict response, it accepts the response. Independent
source audit, source refereeing, two-grader assessment, and substantive
reconciliation are responsible for evaluating quality and disagreement.

Mechanical clarification is limited to information required to interpret and bind
the judgment safely. It is not an informal quality score and must not become a
hidden merits filter.

## Fragmented source review

Protocol 2.1 source review is one response containing as many as 128 proposals.
Protocol 2.2 replaces it with ordered `source_review_fragment` calls.

Each request contains:

- the same frozen source-only record;
- the ordered controller-compiled proposal inventory accepted so far;
- a controller-issued fragment ordinal;
- `max_new_proposals`, initially five; and
- a requirement to declare whether the review is complete.

The issued JSON Schema enumerates the exact `source_id` allowlist from the
frozen record. It also states that each quote must resolve as an exact or
whitespace-normalized unique contiguous substring of that source's normalized
text. When no proposals have been accepted, dependencies are schema-limited to
`null`; otherwise, dependency ordinals are bounded to the supplied inventory.

Each draft contains at most five new semantic proposals and one `review_complete`
boolean. A nonfinal fragment must add at least one new proposal. A final fragment
may add zero to five proposals. The controller compiles proposals, removes only
byte-identical duplicates, assigns canonical proposal references, and seals each
accepted fragment independently.

A subsequent source-review fragment may identify a dependency by the local ordinal
of an accepted proposal supplied in its request. The controller resolves that
ordinal to the canonical proposal reference. The role never authors the canonical
reference.

An early `review_complete` judgment is substantive reviewer output, not proof that
the review is complete. The independent source audit still receives the entire
frozen source record and the complete compiled proposal inventory and may identify
omissions.

The controller permits at most 128 source-review fragments and 640 compiled
proposals in one run. Reaching either resource ceiling without a final fragment
pauses the engine with `DRAFT_LIMIT_EXCEEDED`; it does not conclude the
evaluation. The limit is a resource boundary, not an omission finding.

## Fragmented source audit

Protocol 2.2 also replaces the all-concerns source audit with ordered
`source_audit_fragment` calls.

Each request contains the full frozen source record, complete controller-indexed
review inventory, accepted audit concerns so far, a fragment ordinal, and a
maximum of five new concerns. The draft declares whether the audit is complete.

The audit request carries the same exact source and quote rules, bounds target
and correction-dependency ordinals to the controller inventory, and states the
cross-field concern matrix: omission requires no target and a correction;
ambiguity requires a target and no correction; each `incorrect_*` concern
requires both.

Every concern is independently compiled and sealed. Omission concerns may supply a
new semantic proposal draft, which the controller compiles under the same evidence
and dependency rules. The auditor does not assign proposal or concern identifiers.

The controller permits at most 128 source-audit fragments and 640 compiled
concerns. Reaching either ceiling without completion pauses the engine rather than
creating an evaluation disposition.

Audit completion triggers the existing deterministic dispute inventory. Source
referee fragments, ordinary grade fragments, and contested grade fragments remain
bounded as in Protocol 2.1, but all use the new draft compiler before strict
preflight.

## Recovery and continuation

### Recoverable invariant

An internal draft failure never accepts bytes and never changes the authoritative
run. The current request remains pending in the verified manifest. Therefore:

- a process crash can resume from the exact request already on disk;
- a provider timeout can be retried without recreating accepted work;
- one bad proposal, concern, referee decision, or grade finding does not discard
  previously accepted fragments;
- the driver can stop without assigning an evaluation disposition; and
- a later compatible driver can continue the same run.

### Bounded automatic recovery

One driver invocation may make one initial draft request and at most one fresh
clarification attempt for the same fragment. The clarification role receives:

- the original exact request;
- bounded safe reason codes;
- no rejected draft bytes; and
- no accepted output from an auditor, referee, other grader, or other isolated
  role.

This bound limits automatic cost. It is not a substantive evaluator repair count
and is not persisted as a terminal run fact.

If the clarification draft still cannot compile, the driver returns
`EVALUATION_ENGINE_PAUSED` and exits with a distinct nonterminal engine code. It
does not call an inconclusive-stop transition. The manifest, pending request, and
all accepted artifacts remain byte-identical.

The public CLI exit code for this condition is `6`. Existing exit meanings remain
unchanged.

### Resume API

Protocol 2.2 provides both:

- `continue_evaluation_v22(run_dir, evaluator)`, which starts from a verified
  pending run; and
- a public full-runtime `eval attorney resume --run ...` surface that uses the
  same controller path.

Resume must verify the complete run before invoking any role. It returns the exact
existing pending request, compiles one response at a time, and continues until a
substantive terminal result or another engine pause. Repeated resume is safe.

Portable CLI users retain the existing manual `eval-next` and
`eval-submit-safe` surfaces. A portable automated adapter, if added, must use the
same draft/compiler conformance vectors and produce exact full-runtime bytes.

### Compatible engine correction

Every Protocol 2.2 run binds a `compiler_contract_fingerprint` covering:

- strict response schemas;
- draft schemas;
- normalization tables;
- fragment ordering and size rules;
- evidence-resolution rules; and
- deterministic compiler and aggregate versions.

A corrected runtime may resume an existing Protocol 2.2 run only when it declares
the exact same compiler-contract fingerprint and first verifies all existing
bytes. A correction that changes the contract cannot resume the run in place. It
requires a new run with a new protocol or compiler-contract fingerprint.

This allows implementation defects to be corrected without changing agreed wire
semantics, while preventing a later runtime from silently reinterpreting accepted
history.

## State and terminal semantics

Protocol 2.2 terminal evaluation statuses are substantive only:

- `COMPLETED`; or
- `INCONCLUSIVE` for an approved substantive reason.

`INCONCLUSIVE_MECHANICAL` remains valid only when replaying Protocol 2.1 and older
runs that already contain it. New Protocol 2.2 runs never create it.

`EVALUATION_ENGINE_PAUSED` is a driver outcome, not a manifest terminal status.
The verified run remains in its current nonterminal phase with exactly one pending
request. `eval-status` reports that phase and pending call. `eval-verify` reports a
valid nonterminal run. Neither command claims that the report was evaluated.

Integrity verification failure remains fail-closed. It is not converted into an
engine pause and cannot be resumed until the underlying bytes or storage boundary
are restored to the last verified state.

## Error taxonomy

Protocol 2.2 uses distinct public-safe categories:

1. `DRAFT_NORMALIZED`: a safe mechanical equivalent was compiled automatically.
2. `DRAFT_NEEDS_CLARIFICATION`: the same fragment requires fresh semantic
   clarification.
3. `EVALUATION_ENGINE_PAUSED`: bounded internal recovery ended with the run still
   pending and resumable.
4. `EXTERNAL_RESPONSE_INVALID`: an untrusted strict submission failed preflight
   write-free.
5. `EVALUATION_INTEGRITY_INVALID`: stored bytes, bindings, paths, or replay failed
   strict verification.
6. substantive evaluator findings and terminal dispositions, which remain separate
   from all five mechanical categories.

Diagnostics may expose operation, opaque fragment identity, category, and bounded
reason codes. They must not expose source text, report text, rejected draft bytes,
private paths, provider secrets, or chain-of-thought.

## What remains strict

Protocol 2.2 does not relax acceptance. Before a compiled response is committed,
the existing strict boundary must still prove:

- exact protocol, operation, and request fingerprint;
- exact case, source, report, grader, lane, dispute, batch, and fragment binding;
- allowed fields and enums only;
- exact or uniquely normalized evidence grounded in the request's frozen bytes;
- bounded size, depth, and collection counts;
- complete and nonoverlapping fragment coverage;
- deterministic identifiers, ordering, fingerprints, and aggregates;
- no-follow path containment and immutable artifact ownership;
- manifest-last atomic commit with exact rollback ownership; and
- full semantic replay from frozen inputs and accepted response bytes.

The compiler cannot override a failed strict preflight. A compiler/preflight
disagreement is `EngineDefect`, leaves the run unchanged, and pauses the driver if
the bounded retry cannot resolve it.

### Storage concurrency boundary

The shared evaluator storage contract is
`cooperative-exclusive-directory-namespace-per-operation-v1`. All evaluator
components must coordinate exclusive control of evaluator-owned directory names
during each evaluator storage operation. The storage implementation does not defend against arbitrary same-UID directory rename or replacement between syscalls.
In particular, a same-authority swap after a final successful identity check is
outside this contract; removing that residual would require a different storage
architecture, not an unbounded sequence of check/use assertions.

This boundary does not relax ordinary storage integrity. Implementations still
reject malformed or duplicate-key JSON, stale or tampered bytes, no-clobber
collisions, symlinks, root or directory identity changes they observe, and
component mistakes. They preserve crash-safe rollback and discoverable recovery,
revalidate practical directory bindings after permission changes, and never
report success for a swap or identity change they actually observe. File
publication and rollback recovery retain their no-clobber and ownership-bound
rules.

## Current Protocol 2.1 private run

The completed private Protocol 2.1 run remains immutable and terminal. Protocol
2.2 does not rewrite it, delete it, relabel it, or pretend it reached substantive
evaluation.

The generated candidate and its verified generation capsule remain valid inputs.
After Protocol 2.2 implementation, public stress gates, independent review, and a
separate explicit owner authorization, the same candidate analysis may be
evaluated in one fresh Protocol 2.2 run. That is continuation of the evaluation
work, not mutation of the historical Protocol 2.1 run.

## Protocol compatibility

- Protocols 1.3, 2.0, and 2.1 remain byte-exact replay/read-only.
- Existing runs cannot receive Protocol 2.2 requests or responses.
- Protocol 2.2 uses a new manifest grammar, request operations, artifact namespace,
  compiler contract, and terminal grammar.
- Unknown protocol, draft, compiler-contract, rubric, fragment, aggregate, or
  artifact versions fail closed.
- Full and standard-library portable runtimes must agree exactly on strict
  accepted inputs, artifacts, status, diagnostics, exit codes, replay, and tamper
  behavior.
- New-run default changes only after every public and private readiness gate and a
  separate owner decision.

The Protocol 2.2 operation enum is exactly:

- `source_review_fragment`;
- `source_audit_fragment`;
- `source_referee_fragment`;
- `ordinary_grade_fragment`; and
- `contested_grade_fragment`.

## Security and privacy invariants

Protocol 2.2 preserves:

- source-only reviewer, auditor, and referee packets;
- report blindness and anonymous report labels;
- independent grader isolation;
- controller-owned truthful provider, model, and isolation metadata;
- exact source and report-passage resolution;
- no rejected-draft reuse or persistence;
- bounded input size, depth, fragments, items, and automatic attempts;
- physical path containment and no-follow storage;
- atomic accepted writes and write-free invalid drafts or submissions;
- immutable replay and tamper detection; and
- private artifact exclusion from public packages and public-safe reports.

Draft tolerance applies only before the strict trusted-artifact boundary. It does
not expand the evidence or context visible to any evaluator role.

## Observability

The controller records public-safe operational metrics outside the authoritative
evaluation artifact tree:

- protocol and compiler-contract versions;
- operation and opaque fragment identity;
- compiled on initial or clarification attempt;
- normalization categories used;
- clarification reason categories;
- engine-pause count; and
- resume count.

Metrics must not contain rejected drafts, source or report excerpts, private file
paths, candidate identities, or provider secrets. Loss of telemetry cannot affect
run verification or resume.

## Public verification gate

No private Protocol 2.2 run is authorized until all of the following pass.

### Draft compiler conformance

- every operation compiles a minimal valid draft into exact strict bytes;
- field order, whitespace, and explicit enum-alias variations normalize
  deterministically;
- unique whitespace-normalized evidence resolves to exact frozen bytes;
- ambiguous evidence produces `NeedsClarification` without a write;
- exact duplicates are removed deterministically;
- nonidentical conflicts are never silently merged;
- missing substantive data is never fabricated;
- compiler output always passes the same strict preflight used at commit; and
- full and portable conformance vectors are byte-identical.

### Fragment and resume paths

- source review with zero, one, five, six, 52, 128, and more than 128 proposals;
- source audit with zero, one, five, six, 21, and more than 128 concerns;
- multi-fragment source-review and source-audit crash/resume at every boundary;
- exact pending-request idempotence after process interruption;
- one invalid draft followed by one accepted fresh clarification;
- two invalid drafts producing `EVALUATION_ENGINE_PAUSED` with an unchanged tree;
- successful later resume from that exact pending fragment;
- no repeated accepted fragment after resume;
- no loss of accepted reviewer, auditor, referee, or grade fragments;
- compiler/preflight disagreement pauses without writing; and
- a compatible runtime correction resumes only with the exact contract
  fingerprint.

### Substantive lifecycle paths

- no material disputes;
- reviewer, auditor, and mixed referee outcomes;
- substantive unresolved with outcome-stable `PASS`;
- substantive unresolved with outcome-stable `FAIL`;
- substantive unresolved with outcome-changing `INCONCLUSIVE`;
- two independent graders per report;
- multiple ordinary batches and contested grades; and
- one-report and two-report results.

### Adversarial and compatibility paths

- external malformed strict responses remain write-free and pending;
- cross-case, cross-report, cross-lane, cross-dispute, cross-batch, and
  cross-fragment submissions fail closed;
- quote spoofing, ambiguous normalized quote matching, path traversal, symlink,
  oversized, cyclic, duplicate, aggregate, manifest, result, and resealed tamper
  vectors fail closed;
- interrupted commits roll back only transaction-owned bytes;
- retained Protocol 1.3, 2.0, and 2.1 replay remains byte-identical;
- no retained protocol accepts a mutation; and
- the historical Protocol 2.1 mechanical terminal remains exactly verifiable.

### Stress criterion

The public synthetic stress suite must execute at least 100 deterministic
source-review lifecycles, including large and adversarial draft shapes. Across
valid internally generated semantic drafts:

- zero strict submissions may return `MECHANICAL_RESPONSE_INVALID`;
- zero runs may create an evaluation-ending mechanical terminal;
- every normalizable draft must compile identically in full and portable paths;
- every non-normalizable draft must preserve the exact pending run; and
- every resumed run must reach the same final artifacts as an uninterrupted
  control run.

The full repository test, lint, formatting, typing, package, detached-build,
archive-byte, privacy, owner-marker, isolated-help, and independent-review gates
must also pass.

## Private readiness gate

After the public gate and independent review pass, one separately authorized
private readiness cycle may evaluate the already generated candidate using one
fresh Protocol 2.2 run.

The cycle must bind the exact reviewed commit, package, compiler-contract
fingerprint, generation capsule, candidate report bytes, and frozen sources. It
may use bounded internal clarification and resume as defined here. An engine pause
does not consume the single candidate or authorize a replacement. The same run may
resume because its pending request and accepted artifacts remain unchanged.

Readiness requires a verified substantive terminal result that reaches grading.
A substantive `FAIL` is a completed evaluator result and is not retried. An engine
pause establishes neither readiness nor evaluation failure. Publication, maturity,
performance, or default-protocol changes require a separate explicit owner
decision.

## Acceptance criteria

Protocol 2.2 is ready for implementation planning when the owner approves all of
the following:

1. Internal roles author bounded semantic drafts, not persisted response
   envelopes.
2. Deterministic code owns every identifier, fingerprint, path, order, aggregate,
   and canonical byte representation.
3. Source review and source audit are independently sealed fragments of at most
   five new items.
4. Only mechanically provable equivalences are normalized automatically.
5. Ambiguous or missing substance reissues only the exact affected fragment.
6. Rejected drafts are neither persisted nor shown to a repair role.
7. Exhausted automatic recovery leaves the exact request pending and returns
   `EVALUATION_ENGINE_PAUSED`.
8. A later compatible driver resumes the same run without repeating accepted
   work.
9. New Protocol 2.2 runs never create `INCONCLUSIVE_MECHANICAL`.
10. Substantive unresolved, PASS, FAIL, and INCONCLUSIVE semantics remain those of
    Protocol 2.1.
11. Strict preflight, atomic commit, replay, and tamper verification are not
    weakened.
12. External invalid submissions remain write-free but do not terminalize a run.
13. Protocols 1.3, 2.0, and 2.1 remain exact replay/read-only.
14. The current private Protocol 2.1 record remains immutable, while its generated
    candidate may be used in a separately authorized fresh Protocol 2.2 run.
15. The public stress gate proves zero evaluation-ending internal mechanical
    failures before private execution.

## Required documentation changes

Implementation must update the operator reference, public README maturity wording,
response templates, package manifest, portable reference, error-code reference,
and verification baseline together. Documentation must distinguish:

- semantic drafts from strict accepted responses;
- normalization from substantive correction;
- clarification from evaluator disagreement;
- engine pause from evaluation INCONCLUSIVE;
- current Protocol 2.2 new-run behavior from retained 1.3, 2.0, and 2.1 replay;
  and
- continuation of a pending run from mutation of a historical terminal run.

Results remain AI-generated and require qualified-attorney validation before use
in legal advice.
