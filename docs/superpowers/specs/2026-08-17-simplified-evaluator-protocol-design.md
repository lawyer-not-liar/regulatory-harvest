# Simplified Evaluator Protocol 2.0 Design

**Date:** 2026-08-17  
**Status:** Approved for implementation planning

## Context

Regulatory Harvest's experimental beta established that deterministic source,
citation, provenance, replay, and write-integrity controls are valuable. It
also exposed an architectural imbalance: evaluator roles must currently author
machine-perfect ledgers, identifiers, ordering, relationships, audit findings,
repair transactions, and canonical response envelopes before the evaluation
can reach substantive grading.

The private end-to-end evaluation stopped during ledger auditing rather than on
a substantive result. That stop was correct under the existing fail-closed
contract, but it demonstrated that orchestration mechanics can prevent the LLM
from performing the legal-reasoning work for which it is used. Adding more
prompt detail to the same protocol would preserve the underlying problem.

Protocol 2.0 therefore moves canonical construction into deterministic code
and narrows LLM responsibilities to substantive proposals and judgments.
Determinism remains where it protects a named integrity, privacy, evidence, or
replay risk. It must not prescribe legal reasoning or require an LLM to act as
a serialization engine.

## Goals

- Let LLM roles identify and assess legal requirements, exceptions,
  dependencies, omissions, ambiguities, and evidence in ordinary structured
  form.
- Make deterministic code responsible for identifiers, ordering, normalized
  relationships, canonical artifacts, fingerprints, provenance, and sealing.
- Preserve an independent source-only baseline so candidate and grader do not
  silently share the same omission.
- Produce inspectable requirement-level findings and a narrowly defined,
  versioned `PASS`, `FAIL`, or `INCONCLUSIVE` disposition.
- Reduce evaluator-authored fields, role transitions, mechanical refusals,
  prompt/schema size, portable duplication, and maintenance burden.
- Complete at least one fresh evaluation end to end before declaring protocol
  2.0 ready.
- Preserve exact protocol 1.3 replay without migration or reinterpretation.

## Non-goals

- Do not claim that a passing evaluation proves legal correctness,
  applicability, completeness, or fitness for reliance.
- Do not let deterministic code decide disputed legal substance.
- Do not weaken exact-source verification, citation resolution, privacy,
  provenance, write-free refusal, replay integrity, or attorney-review limits.
- Do not migrate, resume, or rewrite protocol 1.3 runs under protocol 2.0.
- Do not retry a valid substantive result because it is unfavorable.
- Do not introduce replacement candidates, alternate cases, or unbounded role
  loops to obtain a terminal result.

## Chosen architecture

Protocol 2.0 uses **semantic proposals plus a deterministic compiler**.

```text
frozen sources
    -> source reviewer
    -> semantic proposals
    -> independent auditor
    -> material disputes, if any
    -> fresh referee, if needed
    -> deterministic baseline compiler
    -> sealed canonical baseline

sealed baseline + each candidate report
    -> two independent graders per report
    -> requirement-level findings per report
    -> deterministic rubric engine
    -> PASS | FAIL | INCONCLUSIVE per report
```

The source reviewer, auditor, referee, and graders author substantive judgments.
The compiler and rubric engine author canonical artifacts. No LLM role assigns
canonical identifiers, controls walk order, calculates fingerprints, performs
renumbering, emits repair transactions, or reconstructs an entire ledger.

## Role contracts

### Source reviewer

The source reviewer works only from the frozen source record and the versioned
review instructions. It returns a list of semantic proposals. Each proposal
contains:

- a natural-language requirement statement;
- a classification: `obligation`, `prohibition`, `permission`, `exception`,
  `definition`, `deadline`, `enforcement`, or `gap`;
- an importance value: `critical`, `material`, or `supporting`;
- one or more exact source passages with source identifiers;
- an optional natural-language dependency, such as "exception to the reporting
  duty";
- a confidence value: `clear`, `ambiguous`, or `unresolved`; and
- a concise substantive rationale.

The source reviewer does not emit canonical IDs, walk order, normalized graph
edges, scores, fingerprints, hashes, or storage instructions.

### Independent auditor

The auditor receives the frozen sources and the reviewer's proposals. It
returns only suspected defects it judges material to the evaluation. If it
finds no material defect, it returns an empty concern list:

- the proposal's temporary request-local position, when applicable;
- concern type: `omission`, `incorrect_statement`, `incorrect_evidence`,
  `incorrect_relationship`, or `ambiguity`;
- exact source passages; and
- a concise explanation; and
- when acceptance would require changed substance, a proposed natural-language
  correction using the same classification, evidence, dependency, confidence,
  and rationale fields available to the source reviewer.

The auditor does not create a replacement inventory, edit proposals, allocate
IDs, describe mutation transactions, or rebuild a ledger. Its proposed
correction is a substantive option for the referee, not a canonical patch.

### Fresh referee

A referee is invoked only when the controller identifies a material dispute
between reviewer and auditor. For each dispute it returns:

- `accept_reviewer`, `accept_auditor`, or `unresolved`;
- exact supporting passages; and
- a concise substantive rationale.

The referee cannot edit canonical artifacts. An unresolved material dispute is
retained explicitly in the baseline and may make downstream evaluation
`INCONCLUSIVE` under the rubric.

### Deterministic baseline compiler

The compiler:

- validates exact source passages against frozen bytes;
- applies accepted referee decisions;
- assigns stable canonical requirement and evidence identifiers;
- creates deterministic ordering;
- normalizes declared dependencies into typed relationships;
- retains ambiguities and gaps rather than inferring answers;
- constructs canonical provenance and fingerprints; and
- atomically seals the baseline.

The compiler may reject malformed or unresolvable proposals. It may not change
a substantive classification, invent a requirement, resolve an ambiguity, or
select a preferred legal interpretation.

### Independent graders

Two fresh graders independently receive the same sealed baseline, one candidate
report, and versioned rubric. For every engine-supplied requirement ID, each
grader returns:

- `met`, `partially_met`, `not_met`, or `uncertain`;
- exact candidate-report passages, if any;
- concise reasoning; and
- any material omission or unsupported assertion.

A grader may flag a possible baseline defect. It cannot alter the baseline.
Such a defect makes the result `INCONCLUSIVE` unless a separately authorized
human review resolves it outside the automated run.

The graders do not compute aggregate scores, allocate finding IDs, choose
canonical ordering, construct fingerprints, or author final artifacts.

Protocol 2.0 accepts either one candidate report or a blinded candidate and
comparator pair. Each report is graded independently against the same baseline.
The rubric engine may derive a comparison only when both per-report results are
conclusive; it must not force a winner from an `INCONCLUSIVE` result.

### Deterministic rubric engine

The rubric engine validates grader references, compares material findings, and
applies a named, versioned rubric.

- Material grader agreement permits rubric evaluation.
- Material grader disagreement yields `INCONCLUSIVE`; there is no additional
  grading-referee loop.
- A valid unfavorable judgment is accepted without retry.
- Requirement-level findings remain the primary evaluation product.

The terminal disposition has a deliberately narrow meaning:

- `PASS`: the report satisfied this versioned evaluation rubric for this test
  case.
- `FAIL`: the report did not satisfy this versioned evaluation rubric for this
  test case.
- `INCONCLUSIVE`: the evaluator could not establish a reliable result.

None of these labels states that the report is legally correct, complete,
applicable, or safe to rely upon.

## Bounded control flow

A protocol 2.0 evaluation follows this sequence:

1. Verify and freeze sources, candidate report, rubric, prompts, and build.
2. Obtain one source-review response.
3. Obtain one independent-audit response.
4. If material disputes exist, obtain one fresh-referee response.
5. Compile and seal the canonical source-only baseline.
6. Obtain two independent grader responses for each candidate report.
7. Validate and compare the requirement-level findings.
8. Apply the versioned rubric or return `INCONCLUSIVE`.
9. Seal findings, disposition, provenance, and replay data.

Each LLM call permits one initial response and at most one fresh-context repair
for a mechanical defect such as invalid JSON, a missing required field, or an
invalid reference. A second mechanical failure stops the evaluation as
`INCONCLUSIVE`. A rejected response is not committed and is not shown to the
fresh repair role. A schema-valid substantive response is never retried.

Mechanical refusal itself is write-free. After the second refusal, the
controller performs a separate terminal transition containing only the stable
generic stop reason; it never stores rejected-response bytes or details.

The controller must not introduce a replacement candidate, alternate case, or
additional role to force a conclusive result.

## Error and integrity behavior

Deterministic validation remains responsible for:

- canonical JSON and bounded input size/depth;
- exact source and report-passage resolution;
- known source, requirement, and evidence references;
- duplicate and conflicting identifiers after compilation;
- request, response, build, prompt, rubric, and artifact bindings;
- path containment and symlink-safe storage;
- write-free refusal and atomic commit;
- replay and tamper detection; and
- stable public-safe diagnostics.

These checks may refuse malformed data but may not tell a role which legal
answer to reach. Mechanical diagnostics must distinguish schema, citation,
binding, and integrity failures sufficiently for operation without revealing
private content or rejected-response details.

## Storage and replay

Protocol 2.0 uses a distinct run manifest and artifact namespace. Each accepted
artifact records:

- protocol and rubric versions;
- source, candidate, prompt, and build fingerprints;
- operation and request identity;
- truthful provider, model, and isolation metadata;
- accepted-response fingerprint;
- compiler version;
- baseline, findings, and disposition fingerprints; and
- terminal status and reason.

Accepted writes remain atomic. Refused responses remain outside the sealed run.
Private sources, candidate reports, mappings, and detailed evaluation artifacts
remain outside public packages and public-safe reports.

## Protocol compatibility

- Protocol 2.0 is the default for new evaluations after its release gate passes.
- Protocol 1.3 remains readable and byte-exactly replay-verifiable by the 1.3
  verifier.
- A 1.3 run cannot resume with 2.0 operations or schemas.
- No automatic migration rewrites or reinterprets historical artifacts.
- Unknown protocol or rubric versions fail closed.
- Full and stdlib-only portable runtimes must agree on accepted inputs,
  canonical outputs, diagnostics, replay, and tamper results.
- Protocol 2.0 remains explicitly experimental until a fresh end-to-end run
  satisfies every readiness gate.

## Verification strategy

Tests must prove:

- proposal, audit, referee, grader, and rubric schemas reject malformed,
  oversized, cyclic, duplicate, noncanonical, and validation-bypassed inputs;
- exact passages resolve against frozen source and candidate bytes;
- the compiler produces stable identifiers, order, relationships, provenance,
  and fingerprints independent of incidental proposal ordering;
- the compiler preserves material gaps and unresolved disputes;
- no LLM role originates or assigns canonical IDs, artifact order,
  fingerprints, hashes, repair transactions, or aggregate scores; graders may
  only echo engine-supplied requirement IDs to identify their findings;
- one fresh mechanical repair is allowed and a second failure stops;
- valid `FAIL` and `INCONCLUSIVE` responses are never retried;
- material grader disagreement produces `INCONCLUSIVE`;
- full and portable canonical bytes and diagnostics match;
- retained protocol 1.3 capsules replay byte-exactly;
- refused responses do not mutate run storage;
- accepted artifacts commit atomically and detect later tampering; and
- package, privacy, lint, typing, reproducibility, and full-suite gates pass.

## Readiness and success measures

Protocol 2.0 is not ready until one fresh frozen evaluation completes from
source review through terminal grading and all deterministic gates remain
green. That successful run is a hard release gate, not a post-release
aspiration.

The redesign must also demonstrate simplification relative to protocol 1.3:

- materially fewer LLM-authored fields;
- fewer operations and role transitions;
- lower mechanical-refusal rate;
- smaller prompts and response schemas;
- meaningful reduction in evaluator code and portable duplication; and
- no loss of named provenance, evidence, privacy, write-integrity, or replay
  protections.

Exact numeric reduction targets should be recorded from a protocol 1.3 baseline
before implementation and evaluated before the protocol 2.0 release decision.

## Rejected alternatives

### Direct grading without a source-only baseline

Having graders compare the report directly to sources is simpler, but candidate
and grader can share the same omission. It also weakens stable cross-model and
cross-version comparison. The independent source-only baseline is retained.

### Incrementally trimming protocol 1.3

Removing fields while preserving ledger build, audit, repair, referee, and
grading loops has lower migration cost, but it preserves the architecture that
made mechanical construction a prerequisite to substantive grading. Protocol
2.0 uses a clean boundary instead.

### LLM-authored canonical artifacts

Asking an LLM to construct final ledgers, allocate IDs, renumber entries,
remap relationships, or produce repair transactions provides no substantive
reasoning benefit. Those tasks move to deterministic code.

### Single-grader disposition

A single grader is cheaper, but it places too much weight on one model judgment.
Two graders are retained; material disagreement fails closed as
`INCONCLUSIVE` without adding another adjudication loop.

### Unbounded or outcome-directed repair

Additional retries may improve completion rates but encourage feedback-driven
overfitting and can turn the controller into a mechanism for obtaining a
preferred result. Protocol 2.0 permits only one fresh mechanical repair per
call and never retries valid substance.
