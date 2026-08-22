# Evaluator Protocol 2.1 Fragmented Adjudication Design

**Author:** Earl Mah
**Created:** 2026-08-18
**Last updated:** 2026-08-18
**Status:** Approved for implementation planning
**Supersedes for new runs:** Protocol 2.0 control flow
**Compatibility:** Protocols 1.3 and 2.0 remain replay-only

## Context

Protocol 2.0 correctly moved canonical envelopes, identifiers, ordering,
fingerprints, storage, and baseline compilation out of evaluator roles. A fresh
private readiness rerun demonstrated that this boundary repair worked:

- the initial source-review response was accepted;
- the source audit was accepted after one fresh mechanical repair; and
- the run advanced to source refereeing.

The referee then had to resolve 21 disputes in one response. Its initial response
and sole fresh repair were both refused write-free with the same mechanical
diagnostic. The verified run stopped `INCONCLUSIVE` before grading.

This was not a recurrence of the envelope defect. It exposed the same broader
failure pattern at a later boundary: an LLM must still produce a large,
all-or-nothing structured artifact before the controller can preserve any of its
substantive judgments. One mechanical defect discards every otherwise usable
decision in the response.

Protocol 2.1 reduces the evaluator-authored unit of work. Deterministic code keeps
integrity and aggregation responsibilities. Evaluator roles make small semantic
judgments. Genuine legal uncertainty remains representable without being confused
with mechanical failure.

## Goals

- Preserve independent source review, source audit, refereeing, and two-grader
  assessment.
- Resolve each material source dispute as an independently sealed semantic
  judgment.
- Preserve both supported interpretations when a referee substantively concludes
  that a dispute is unresolved.
- Continue grading when unresolved disputes do not affect the report disposition.
- Return substantive `INCONCLUSIVE` only when an unresolved dispute is
  outcome-determinative or prevents meaningful grading.
- Grade ordinary requirements in bounded batches and contested requirements
  individually.
- Resume at the exact pending fragment without repeating accepted judgments.
- Keep mechanical failure distinct from substantive uncertainty.
- Preserve exact evidence, blinding, provenance, privacy, atomic writes, replay,
  and full/portable parity.
- Complete the full public verification gate before authorizing another private
  readiness run.

## Non-goals

- Do not send referee decisions back to the source reviewer for revision.
- Do not let the reviewer validate or rewrite its own work after audit.
- Do not let deterministic code choose between disputed legal interpretations.
- Do not treat a malformed response, failed repair, timeout, or low confidence as
  substantive `unresolved`.
- Do not end an evaluation merely because it contains a fixed number or percentage
  of unresolved disputes.
- Do not grade an incompletely compiled baseline after a mechanical hard stop.
- Do not add a grader-referee loop.
- Do not migrate, rewrite, or resume Protocol 1.3 or 2.0 runs as Protocol 2.1.
- Do not weaken exact-source or exact-report-passage validation.
- Do not run repeated private readiness cycles while developing Protocol 2.1.

## Architectural decision

Protocol 2.1 uses a common canonical baseline plus explicitly contested
requirements.

```text
frozen sources
    -> source reviewer
    -> independent source auditor
    -> deterministic dispute inventory
    -> one referee call per dispute
    -> deterministic resolution aggregate
    -> common requirements + contested requirements
    -> sealed canonical baseline

sealed baseline + candidate report
    -> two independent graders
    -> ordinary requirements in batches of at most five
    -> contested requirements one at a time
    -> deterministic grade aggregates
    -> deterministic outcome-sensitivity analysis
    -> PASS | FAIL | INCONCLUSIVE
```

The source reviewer and source auditor contracts remain unchanged because both
produced accepted live responses. Protocol 2.1 changes the referee, baseline,
grading, manifest, storage, aggregation, and replay contracts.

## Source-referee contract

### One dispute per call

The controller converts the accepted source review and source audit into a stable,
ordered dispute inventory. Each pending referee call contains exactly one dispute:

- the reviewer proposal, if any;
- the auditor concern and proposed correction, if any;
- the exact controller-resolved source passages supporting both alternatives;
- the dispute's importance and affected requirement context; and
- the operation-specific response schema.

The controller owns the dispute identifier, call identifier, artifact path,
request fingerprint, ordering, and response envelope. The referee does not echo
those values in its inner payload.

Each dispute is judged in a fresh referee context. No accepted or rejected
referee response is supplied as evidence for another dispute.

### Referee response

The referee must make exactly one of these determinations:

- `accept_reviewer`
- `accept_auditor`
- `unresolved`

Every response includes a concise substantive rationale and selects only
controller-issued evidence references. It does not author source quotations,
offsets, canonical requirement identifiers, or storage metadata.

An `unresolved` determination additionally requires exactly one substantive reason
code:

- `SOURCE_AMBIGUITY`
- `SOURCE_CONFLICT`
- `SOURCE_GAP`
- `BOTH_POSITIONS_UNSUPPORTED`

`unresolved` is a completed legal judgment that the closed evidence cannot
responsibly resolve the dispute. It is not abstention from performing the role and
is not a fallback for invalid output.

### Referee aggregation

Each accepted referee fragment is sealed independently. After every dispute has an
accepted response, deterministic code constructs one resolution aggregate in
dispute order.

- `accept_reviewer` retains the reviewer proposal.
- `accept_auditor` applies the auditor correction or accepted omission.
- `unresolved` retains both supported alternatives as a contested requirement.

The aggregate records fragment fingerprints and engine-issued dispute identities.
No evaluator role authors or edits the aggregate.

## Contested requirements

A contested requirement is not silently collapsed into either alternative. It
contains:

- one engine-issued contested-requirement identifier;
- the reviewer alternative and its resolved evidence;
- the auditor alternative and its resolved evidence;
- the substantive unresolved reason code and rationale;
- importance and dependency context; and
- the accepted referee-fragment fingerprint.

The common baseline contains all uncontested canonical requirements plus the
contested-requirement inventory. It preserves both interpretations without
asserting that either is controlling law.

The mere presence or number of contested requirements does not determine the
terminal disposition. Their effect is assessed during grading.

## Bounded grading

### Independent graders

Two independent graders remain required for each candidate report. They receive
the same sealed baseline, report bytes, and versioned rubric. A grader never sees
the other grader's response.

Each report uses two logical grader lanes that begin in contexts isolated from one
another. Every grade-fragment request is evidence-complete and must not rely on
hidden conversation state. Accepted fragments within one lane may be processed
sequentially by the same isolated context for efficiency, but resume may use a new
truthfully labeled context because the request carries the complete evidence. A
mechanical repair always uses a genuinely fresh context and never receives rejected
response content.

### Ordinary requirements

The controller divides uncontested requirements into deterministic batches of at
most five requirements. Each grade-fragment request identifies the engine-issued
requirements in that batch. Each response must cover every supplied requirement
exactly once and no other requirement.

The grader supplies only substantive dispositions, concise reasoning, and exact
candidate-report passages. The controller owns batch ordering, finding identifiers,
fingerprints, and aggregate construction.

### Contested requirements

Each contested requirement receives its own grade-fragment request. For both the
reviewer and auditor alternatives, the grader assesses whether the report:

- satisfies the alternative;
- partially satisfies it;
- does not satisfy it; or
- cannot be assessed from the report.

The grader also determines whether the report accurately acknowledges the
ambiguity, overstates one interpretation as settled, or omits the issue. It binds
those judgments to exact report passages when present.

### Grade aggregation

Accepted grade fragments are sealed independently. Deterministic code verifies
complete, nonoverlapping coverage and constructs one grade aggregate per grader.
The existing two-grader reconciliation remains deterministic. There is no grading
referee.

## Outcome-sensitivity rule

Unresolved source disputes do not automatically make the evaluation
`INCONCLUSIVE`.

For each contested requirement, deterministic code calculates the report outcome
under both supported alternatives using the reconciled grader findings and the
versioned rubric.

- If the absolute report disposition is the same under both alternatives, the
  dispute is outcome-stable and the evaluation may return that `PASS` or `FAIL`.
- If the absolute disposition changes between alternatives, the dispute is
  outcome-determinative and the evaluation returns substantive `INCONCLUSIVE` with
  reason `OUTCOME_SENSITIVE_BASELINE_DISPUTE`.
- If the report accurately explains the ambiguity and satisfies the rubric under
  both alternatives, the dispute does not prevent `PASS`.
- If the report materially overstates a disputed interpretation as settled, the
  rubric may produce a stable `FAIL` under both alternatives.
- If the evidence gap prevents either alternative from being graded meaningfully,
  the evaluation returns substantive `INCONCLUSIVE` with reason
  `BASELINE_EVIDENCE_INSUFFICIENT`.

One central unresolved dispute may be outcome-determinative. Many peripheral
unresolved disputes may be outcome-stable. No raw-count threshold substitutes for
this analysis.

## Mechanical failure and substantive uncertainty

Protocol 2.1 records these as different terminal causes.

### Substantive unresolved

A schema-valid referee response selects `unresolved` with an allowed reason code,
rationale, and evidence references. The response is committed as a substantive
judgment, the baseline records both alternatives, and grading continues.

### Mechanical refusal

A malformed, unbound, oversized, invalidly referenced, or otherwise mechanically
invalid response is refused write-free. The controller permits one repair in a
genuinely fresh context for that exact fragment. The repair receives the original
request only and never receives rejected-response content.

If the repair is also refused, the authoritative evaluation stops as
`INCONCLUSIVE_MECHANICAL`. It records the safe operation and fragment identity but
does not store rejected bytes or private diagnostic detail. The controller does not
convert that failure into substantive `unresolved` and does not grade an incomplete
baseline or grade aggregate.

The same initial-plus-one-repair bound applies to every referee and grade fragment.
A valid unfavorable substantive response is accepted without retry.

## Manifest, storage, and resume

Protocol 2.1 uses a new manifest grammar and artifact namespace. At minimum, the
sealed run records:

- the ordered referee-dispute inventory;
- one request and accepted response fingerprint per completed referee fragment;
- the deterministic referee aggregate;
- the common and contested baseline fingerprints;
- deterministic ordinary-grade batch inventories per report and grader;
- one request and accepted response fingerprint per completed grade fragment;
- one deterministic grade aggregate per grader;
- the sensitivity-analysis fingerprint; and
- the terminal disposition and reason.

The next pending fragment is derived from the manifest's accepted inventory. Resume
must:

- verify every accepted artifact before issuing another request;
- return the exact already-issued pending request when one exists;
- never repeat an accepted referee or grade judgment;
- never renumber disputes, requirements, batches, or fragments;
- reject swapped fragments across disputes, reports, graders, or batches; and
- preserve atomic commit and write-free refusal.

An interrupted process resumes at the exact pending fragment. It never reconstructs
or resubmits the complete referee or grader response.

## Protocol compatibility

- Protocol 2.1 is a distinct new-run protocol because its request sequence,
  manifest grammar, and artifacts differ materially from Protocol 2.0.
- Protocol 1.3 remains byte-exact replay/read-only.
- Protocol 2.0 remains byte-exact replay/read-only.
- Existing 1.3 or 2.0 runs cannot resume with 2.1 requests or responses.
- No migration rewrites or reinterprets historical run bytes.
- Unknown protocol, rubric, fragment, or aggregate versions fail closed.
- Full and standard-library portable runtimes must agree exactly on accepted
  inputs, requests, responses, artifacts, status, diagnostics, exit codes, replay,
  and tamper behavior.
- Protocol 2.1 becomes the default only after every readiness gate in this design
  passes.

## Security and privacy invariants

Protocol 2.1 preserves:

- source-only reviewer, auditor, and referee packets;
- report blindness and anonymous report labels;
- independent grader isolation;
- controller-owned truthful provider, model, and isolation metadata;
- exact source and report-passage resolution;
- no rejected-response reuse or disclosure;
- bounded input size, depth, and collection counts;
- physical path containment and no-follow storage;
- atomic accepted writes and write-free refusal;
- immutable replay and tamper detection; and
- private artifact exclusion from public packages and public-safe reports.

Smaller packets do not authorize broader context. Every role receives only its
current request as evidence.

## Public verification gate

Protocol 2.1 must pass all of these gates before another private readiness run is
authorized.

### Functional paths

- no material disputes;
- multiple disputes resolved for the reviewer;
- multiple disputes resolved for the auditor;
- mixed referee outcomes;
- substantive unresolved with an outcome-stable `PASS`;
- substantive unresolved with an outcome-stable `FAIL`;
- substantive unresolved with an outcome-changing `INCONCLUSIVE`;
- insufficient baseline evidence producing substantive `INCONCLUSIVE`;
- one-report and two-report evaluation;
- two independent graders per report; and
- ordinary final `PASS`, `FAIL`, and nonmechanical `INCONCLUSIVE`.

### Mechanical and resume paths

- invalid initial referee fragment followed by one accepted fresh repair;
- second referee-fragment refusal producing verified
  `INCONCLUSIVE_MECHANICAL`;
- invalid initial grade fragment followed by one accepted fresh repair;
- second grade-fragment refusal producing verified
  `INCONCLUSIVE_MECHANICAL`;
- interruption and resume after partially completed referee fragments;
- interruption and resume after partially completed grade batches;
- no repeated accepted judgments after resume;
- exact pending-request idempotence;
- fragment swap, omission, duplication, and tamper refusal;
- aggregate swap and tamper refusal; and
- exact no-write snapshots for every refusal.

### Compatibility and release paths

- retained Protocol 1.3 replay remains byte-identical;
- retained Protocol 2.0 replay remains byte-identical;
- full and isolated portable Protocol 2.1 lifecycle parity is exact;
- canonical package manifests include every required Protocol 2.1 runtime asset;
- two detached exact-commit builds are byte-identical;
- every archive member matches its Git blob;
- clean extraction and isolated help work;
- repository, archive, privacy, and owner-marker audits report no automated
  findings;
- the full test suite, configured lint, formatting, and typing gates pass; and
- independent review reports no Critical or Important finding.

## Private readiness gate

After the public gate and independent review pass, one separately authorized fresh
private readiness cycle may run against the exact reviewed commit and package.

The private cycle must use:

- one freshly admitted source-only qualification;
- one generated candidate from the exact captured build;
- one Protocol 2.1 evaluation;
- one initial response and at most one fresh repair per fragment;
- no replacement candidate, alternate case, or repeated cycle; and
- full and isolated replay verification of every terminal artifact.

A readiness PASS requires a substantive terminal evaluation that reaches grading.
A verified substantive `FAIL` is a completed evaluator result and is not retried.
A mechanical terminal state does not establish readiness. No publication,
performance claim, or default-protocol change follows without a separate explicit
owner decision.

## Acceptance criteria

Protocol 2.1 is ready for implementation review when all of the following are true:

1. Every referee request contains exactly one engine-issued dispute.
2. Every referee response contains exactly one semantic determination and no
   engine-owned identifier or artifact metadata.
3. Substantive unresolved decisions require one approved reason code and valid
   evidence references.
4. Contested requirements preserve both alternatives without deterministic legal
   selection.
5. Ordinary grade batches contain at most five requirements.
6. Each contested requirement is graded individually by both graders.
7. Deterministic aggregation proves complete, nonoverlapping fragment coverage.
8. Outcome-stable disputes permit conclusive PASS or FAIL.
9. Outcome-changing disputes produce substantive INCONCLUSIVE.
10. Mechanical failure is never relabeled substantive unresolved.
11. Resume never repeats an accepted judgment.
12. Protocols 1.3 and 2.0 remain byte-exact replay/read-only.
13. Full and portable Protocol 2.1 behavior is byte-identical.
14. Every public verification gate passes before private execution.
15. No maturity, performance, or publication claim exceeds the observed private
    evidence.

## Rejected alternatives

### Return referee output to the reviewer

Letting the reviewer revise after seeing the audit or referee result creates
self-validation and anchoring. It also recreates a large proposal response and
weakens independent source adjudication.

### One all-disputes referee response

This preserves the Protocol 2.0 failure mode. A single mechanical defect discards
every substantive decision and forces full reconstruction in a repair context.

### Always force reviewer or auditor acceptance

Forcing a binary winner manufactures certainty when authorities conflict, are
ambiguous, omit a necessary rule, or support neither position.

### Any unresolved dispute forces INCONCLUSIVE

This treats peripheral uncertainty as outcome-determinative and prevents a report
from passing even when it accurately explains a close question and performs the
same under both supported interpretations.

### Raw unresolved-count threshold

One central dispute may control the result while many peripheral disputes may not.
Material outcome sensitivity is a better decision rule than a fixed number or
percentage.

### Grade the complete baseline twice

Compiling two full baselines and repeating every grade doubles cost and creates
additional cross-run consistency risks. Protocol 2.1 grades a common baseline once
and evaluates each contested requirement against both alternatives.

### Continue after exhausted mechanical repair

Continuing an authoritative run with a missing referee or grade fragment would
produce an incompletely bound baseline or grade aggregate. Mechanical hard stop
remains fail-closed and separately labeled.

## Required documentation changes

Implementation must update the operator reference, public README maturity wording,
response templates, package manifest, portable reference, and verification baseline
together. Documentation must distinguish:

- Protocol 1.3 replay-only behavior;
- Protocol 2.0 replay-only behavior;
- Protocol 2.1 new-run behavior;
- substantive unresolved uncertainty;
- mechanical terminal failure; and
- the limited meaning of PASS, FAIL, and INCONCLUSIVE.

Results remain AI-generated and require qualified-attorney validation before use in
legal advice.
