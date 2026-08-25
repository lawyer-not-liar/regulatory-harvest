# Review-Ready Delivery and Stable Baseline Design

**Author:** Earl Mah
**Created:** 2026-08-24
**Last updated:** 2026-08-24
**Status:** Approved for implementation planning
**Applies after:** Published `v0.1.0-beta.8`
**Compatibility:** Protocols 1.3, 2.0, 2.1, and 2.2 remain byte-for-byte replay-only; their dispositions, exit codes, manifests, results, and run trees do not change

## Context

Protocol 2.2 beta.8 completed a real private evaluation without a mechanical
failure. Fourteen distinct fresh evaluator roles were accepted on their first
attempt. Full and isolated-portable status and verification outputs matched,
and the sealed run verified successfully.

The remediated report nevertheless received terminal `FAIL`. Nine requirements
were `met` in both grader lanes. Three were `partially_met` in both lanes, and
one was `partially_met` in one lane and `met` in the other. The first lane had
critical recall `0.90` and weighted coverage `0.8611`; the second had critical
recall `0.95` and weighted coverage `0.9028`.

That result exposed two separate product questions that the current binary
disposition conflates:

1. Did the report satisfy the locked high-assurance rubric?
2. Is the evidence-bound report still useful as an attorney-review starting
   point when every known omission is clearly disclosed and assigned for
   follow-up?

It also exposed a cross-run fairness defect. With unchanged sources, question,
case, and rubric, one report-blind source process produced seven requirements,
two critical; a later report-blind process produced thirteen requirements, ten
critical. The report rewrite could not cause that change because source review,
source audit, and source referee packets contained no report bytes. Some finer
decomposition was legitimate, but the change in coverage, overlap, and critical
prevalence proves that report remediation currently faces a moving target.

The product should preserve the strict high-assurance score while also
delivering useful, candid work product. It should make known gaps actionable,
not suppress the whole report merely because it falls short of the highest
quality tier.

## User-visible requirement

For every verified report evaluation, the system must answer two orthogonal
questions:

> What did the strict evaluation rubric conclude, and may a qualified attorney
> safely use this report as a starting point when the remaining gaps and
> required follow-up are explicit?

The attorney must receive the report, its requirement-by-requirement matrix,
and an actionable gap-and-follow-up matrix whenever the work is review-ready.
`HIGH_ASSURANCE` is not required for attorney review. `NOT_DELIVERABLE` is
reserved for work whose provenance, evidence, candor, or minimum usefulness is
insufficient.

## Terminology

### Strict evaluation disposition

The existing Protocol 2.2 `PASS`, `FAIL`, or substantive `INCONCLUSIVE` result.
It remains unchanged and continues to answer whether the report satisfied the
locked strict rubric.

### Delivery readiness

An additive, versioned determination with exactly three values:

- `HIGH_ASSURANCE`
- `REVIEW_READY_WITH_GAPS`
- `NOT_DELIVERABLE`

Delivery readiness never rewrites the strict disposition and never claims legal
correctness, completeness, currentness, applicability, or advice suitability.

### Stable baseline

A report-blind, sealed inventory of canonical requirements and relationships
for one exact legal evidence record. It is reusable across report revisions
only while all legal-input bindings remain identical.

### Visible gap

A partial, missing, uncertain, contested, or safety-related shortfall that is
stated in the attorney-facing report, represented in the gap matrix, and paired
with a concrete follow-up owner and action. It also states why the shortfall
exists, why it matters, and what evidence or decision would resolve or narrow it.

### Blocking defect

A defect that makes delivery unsafe regardless of the report's numerical score,
including invalid provenance or replay, hidden material limitations, materially
unsupported assertions, misleading contradictions, or an unbound dispositive
client-fact dependency.

## Goals

- Preserve strict `PASS` as the high-assurance tier.
- Deliver useful reports that honestly identify material gaps.
- Make each known gap actionable for the reviewing attorney or outside counsel.
- Require an evidence-grounded, plain-language rationale for every gap; a code,
  label, score, or generic statement that more research is needed is
  insufficient.
- Reserve nondelivery for unsafe, misleading, invalid, or insufficient work.
- Stabilize the source-derived requirement baseline across report revisions.
- Define `critical`, `material`, and `supporting` operationally.
- Require source audit and referee review of importance assignments.
- Preserve exact source, report, capsule, request, response, manifest, hash,
  storage, replay, and full/portable bindings.
- Add the new workflow without modifying any retained run byte.
- Support pause, resume, crash recovery, verification, and deterministic replay.
- Keep Protocol 2.1 as the default until the new workflow earns its own public
  and private readiness evidence.

## Non-goals

- Do not relabel a historical Protocol 2.2 `FAIL` as `PASS`.
- Do not weaken the existing 1.0 critical-recall or 0.90 weighted-coverage
  floors for `HIGH_ASSURANCE`.
- Do not hide, delete, merge away, or downgrade a genuine gap to obtain a more
  favorable readiness tier.
- Do not treat `REVIEW_READY_WITH_GAPS` as authorization for unreviewed client
  delivery.
- Do not make outside counsel responsible for discovering gaps the system
  already knows.
- Do not make the attorney edit JSON, operate the controller, or reconstruct
  evaluator reasoning.
- Do not make a report revision regenerate the source baseline when the legal
  inputs are unchanged.
- Do not reuse a baseline after a source, question, jurisdiction, as-of date,
  requested-authority scope, rubric, compiler, or baseline-policy change.
- Do not embed a companion artifact inside a retained Protocol 2.2 run.
- Do not publish, change the default protocol, or claim production maturity
  through implementation of this design alone.

## Considered approaches

### Lower the existing `PASS` thresholds

This would make more reports pass but would erase the distinction between an
exceptionally complete report and a useful report with known gaps. It would
also allow a partial critical requirement to satisfy the high-assurance label.

**Decision:** rejected. Keep strict `PASS` and add an orthogonal delivery tier.

### Treat every verified `FAIL` as deliverable

This would maximize output but could deliver misleading work, hidden material
omissions, unsupported assertions, or reports too incomplete to be useful.

**Decision:** rejected. Review-ready reports must satisfy provenance, candor,
minimum coverage, and safety gates.

### Require 85% weighted coverage for the middle tier

This would create only a five-point band between review-ready and the existing
90% high-assurance floor. The middle tier would not materially solve the user's
need for useful starting work product.

**Decision:** rejected. Use an initial conservative minimum-lane floor of 70%.
Version and recalibrate it against attorney-reviewed cases.

### Add fields directly to Protocol 2.2 result artifacts

Protocol 2.2 replay reconstructs exact result and manifest bytes and rejects
unbound artifacts. In-place additions would invalidate retained runs or silently
change the meaning of the `2.2` label.

**Decision:** rejected. Use a separate versioned companion graph. If a future
main evaluation protocol embeds these semantics, it must use a new protocol
version.

### Rebuild the source baseline for every report revision

This preserves fresh source judgment but makes the target examiner-dependent.
The private evidence showed requirements changing from 7 to 13 and critical
prevalence changing from 28.6% to 76.9% without a legal-input change.

**Decision:** rejected for revision comparisons. Build once, seal, and reuse.

## Architecture

The design has two independently testable companion protocols:

1. `evaluation-baseline-v1` creates and verifies the report-blind legal
   baseline.
2. `delivery-readiness-v1` binds a verified report evaluation to that baseline,
   performs report-wide safety review, and derives the readiness tier and gap
   matrix.

Neither protocol adds files to a Protocol 2.2 run. Both live in separate sibling
directories under the approved control root, use immutable artifact storage,
and bind their source artifacts by exact fingerprints.

The first implementation may consume a verified Protocol 2.2 run as historical
evidence while deriving the initial baseline and readiness record. Subsequent
report revisions for the same legal inputs use the sealed baseline and run fresh
baseline-locked grading and safety roles against the revised report. They do not
repeat report-blind source review, depend on a newly regenerated Protocol 2.2
baseline, or guess a crosswalk between independently generated requirements.

The readiness compiler applies the exact retained Protocol 2.2 grading credit,
critical-recall, weighted-coverage, lane-reconciliation, and sensitivity rules
to its fresh baseline-locked grading lanes. It records that result as
`baseline_locked_strict_equivalent_disposition`. When an older verified Protocol
2.2 run is supplied, its disposition is preserved separately as
`historical_v22_strict_disposition` and may be compared only after exact baseline
identity is proven. No retained Protocol 2.2 artifact, command, default, or
result is rewritten.

## Stable baseline protocol

### Identity

The reusable baseline identity binds:

- exact normalized source bytes and source IDs;
- source-record fingerprint;
- exact research question;
- jurisdiction;
- as-of date;
- requested-authority scope;
- exact client-fact bytes, including an explicit null binding when none exist;
- qualification capsule root and readiness status;
- compiler contract fingerprint;
- rubric version and bytes;
- importance-policy version; and
- source-review, source-audit, and referee provenance.

It excludes:

- candidate identifier;
- report text or report hash;
- anonymous report labels;
- generation metadata;
- grader responses;
- run seed; and
- any report-bound case fingerprint.

### Importance definitions

Every source-review, audit, and referee packet includes these operational
definitions:

- `critical`: omission or material misstatement could change the legal bottom
  line, applicability, operative status, core duty or prohibition, enforcement
  exposure, remedy, or a dispositive deadline.
- `material`: necessary for a competent attorney briefing or implementation
  decision but not independently outcome-determinative under the current scoped
  question.
- `supporting`: useful explanatory, contextual, or implementation detail whose
  absence does not materially change the legal answer or required next action.

Each proposal and correction includes a nonblank importance rationale tied to
one definition. Source audit explicitly reviews importance, and any disagreement
becomes a referee decision. The compiler rejects unreasoned importance labels.

### Reuse and correction

A report-only byte change reuses the baseline. Any bound legal-input change
requires a new baseline.

A baseline correction is allowed only through a separate, versioned,
attorney-approved correction record that:

- identifies the exact prior baseline;
- identifies the affected requirement or relationship;
- states the correction reason without report content;
- creates a new baseline fingerprint; and
- never rewrites the old baseline.

## Delivery-readiness protocol

### Inputs

The readiness run binds:

- verified baseline root and fingerprint;
- verified qualification root and receipt;
- verified generation capsule root and report hash;
- deterministic generation validation receipt;
- exact strict evaluation manifest root and result fingerprint when a verified
  Protocol 2.2 result is supplied as historical evidence;
- both fresh baseline-locked grader-lane aggregates and their sensitivity
  record; and
- readiness rubric version and bytes.

### Baseline-locked report grading

Every readiness run grades the exact candidate report against the exact sealed
baseline through two fresh isolated lanes. The controller projects the verified
baseline into one canonical gradeable shape; both lanes receive byte-identical
requirements, relationships, evidence handles, importance assignments and
rationales, with only their controller-issued lane identity differing. The
projection fingerprint is stored in the readiness input and must match every
grading request and result.

The stable-baseline implementation exposes this handoff as
`project_gradeable_baseline_v1(VerifiedBaselineContextV1) ->
GradeableBaselineProjectionV1`. Readiness must pass the candidate projection
through `verify_gradeable_baseline_projection_v1(...)` before issuing a grading
request. These adapters are exact byte-and-fingerprint checks, not semantic
similarity or inferred requirement mapping.

The readiness compiler uses the retained Protocol 2.2 scoring semantics without
calling or modifying a retained Protocol 2.2 run. It therefore produces a
current strict disposition for each report revision while holding the legal
baseline fixed. A supplied historical Protocol 2.2 result is never substituted
for these fresh grades. If its baseline can be proven byte-equivalent, the
readiness record may expose the historical disposition as a comparison only
when its report hash also matches. A different baseline is
`BASELINE_NOT_COMPARABLE`; a different report revision is
`REPORT_NOT_COMPARABLE`. In both cases the old result remains bound provenance
and no semantic comparison is claimed.

### Report-wide safety review

Requirement grading alone cannot prove that a report lacks materially
unsupported assertions or hidden limitations. The readiness run therefore
issues two fresh, isolated, report-wide safety-review requests. Each receives
only the stable baseline, exact report, exact source record, qualification
limits, client-fact boundary, and readiness safety schema.

Each safety lane reports only controller-bound findings for:

- material unsupported assertion;
- contradiction of the sealed baseline;
- hidden or materially understated limitation;
- undisclosed dispositive client-fact dependency;
- misleading treatment of currentness, operative status, authority, source
  parity, or language limits; and
- a gap represented in grader evidence but not visibly disclosed in the report.

The controller owns finding IDs, ordering, fingerprints, canonicalization, and
the final matrix. One blocking finding in either lane blocks delivery. A
disagreement remains visible and is resolved only by a fresh dispute-scoped
safety referee; the controller never silently selects the favorable lane.

### Gap and follow-up matrix

The deterministic matrix contains one row for every:

- `partially_met`, `not_met`, or `uncertain` requirement in either lane;
- baseline requirement whose kind is `gap`;
- unresolved contested requirement;
- report-wide safety finding; and
- missing or limited qualification, generation, currentness, language, or
  client-fact prerequisite.

Each row contains:

- `gap_id`;
- `origin`;
- `subject_id`;
- `kind`;
- `importance`;
- both lane dispositions;
- conservative disposition;
- exact report passages when present;
- nonblank omission or uncertainty description;
- `rationale_kind` from the fixed inventory below;
- plain-language `why_unresolved`;
- evidence-grounded `why_it_matters`;
- report location where the gap is disclosed;
- `visibility`;
- `blocking_code` when applicable;
- deterministic `follow_up_code`;
- plain-language `resolution_test` describing the evidence, fact, legal
  judgment, or report correction that would resolve or materially narrow the
  gap;
- `owner_role` of `reviewing_attorney`, `outside_counsel`, or
  `research_operator`; and
- `status` of `open` or `resolved`.

A partial, missing, or uncertain row without an exact report binding when
content is present, a nonblank shortfall description, a visible disclosure, and
a follow-up code is a blocking hidden gap.

## Gap-rationale contract

Every matrix row must articulate the reason for the gap rather than merely name
it. `rationale_kind` is exactly one of:

- `REPORT_OMISSION`
- `REPORT_PARTIAL_TREATMENT`
- `SOURCE_ABSENT`
- `SOURCE_AMBIGUOUS`
- `SOURCE_CONFLICT`
- `CURRENTNESS_NOT_ESTABLISHED`
- `APPLICABILITY_FACT_MISSING`
- `LANGUAGE_LIMITATION`
- `CONTESTED_INTERPRETATION`
- `UNSUPPORTED_ASSERTION`
- `SAFETY_REVIEW_FINDING`

The evaluator or safety reviewer supplies the substantive components in its
bounded response. The controller validates and compiles them; it never invents a
legal rationale from a score or reason code.

`why_unresolved` must identify the concrete missing treatment, evidence limit,
fact, conflict, or interpretive question. `why_it_matters` must connect that
shortfall to the scoped legal conclusion, applicability analysis, implementation
decision, deadline, enforcement exposure, or attorney follow-up. `resolution_test`
must state what observable evidence or correction would close or materially
narrow the row.

The following are invalid on their own:

- `more research needed`;
- `insufficient information`;
- `requirement partially met`;
- a repeated disposition or reason code;
- a score without an explanation; or
- a conclusion that the gap is material without explaining the consequence.

The compiler rejects a missing, blank, generic, internally contradictory, or
evidence-unbound rationale. When available evidence cannot support a more
specific explanation, the row becomes blocking rather than permitting the
controller to fabricate one. The attorney-facing handoff renders the rationale
as `What is missing`, `Why it matters`, `How to resolve it`, and `Owner`.

### Follow-up codes

The initial fixed inventory is:

- `VERIFY_PRIMARY_AUTHORITY`
- `CONFIRM_CURRENTNESS`
- `RESOLVE_APPLICABILITY_FACT`
- `OBTAIN_OUTSIDE_COUNSEL_ANALYSIS`
- `EXPAND_REQUIREMENT_ANALYSIS`
- `CORRECT_UNSUPPORTED_ASSERTION`
- `RESOLVE_LANGUAGE_LIMITATION`
- `RESOLVE_CONTESTED_INTERPRETATION`

The matrix may combine several rows under one attorney-facing action, but it may
not omit or merge away a row.

## Deterministic readiness rubric

### `HIGH_ASSURANCE`

All of the following are required:

- qualification, generation, baseline, evaluation, readiness, replay, and
  full/portable parity checks pass;
- strict evaluation disposition is `PASS`;
- both grader lanes have critical recall `1.0` and weighted coverage at least
  `0.90`;
- no blocking baseline gap, outcome-determinative unresolved contest, or safety
  finding remains;
- every partial or other nonblocking shortfall permitted by the strict rubric is
  still visible in the gap matrix with its follow-up;
- deterministic generation validation is `completed`; and
- proposition coverage, provision recall, and evidence precision are true.

### `REVIEW_READY_WITH_GAPS`

All of the following are required:

- every provenance, storage, replay, qualification, generation, baseline, and
  parity check passes;
- the report has a verified substantive evaluation result; a strict `FAIL` or
  substantive `INCONCLUSIVE` does not by itself block review readiness;
- the conservative minimum weighted coverage across grader lanes, counting
  `met=1.0`, `partially_met=0.5`, and `not_met` or `uncertain=0.0`, is at least
  `0.70`;
- every non-met requirement is represented in the gap matrix;
- every gap satisfies the gap-rationale contract;
- every critical shortfall is prominently disclosed in the Executive Summary
  or the report's consolidated limitations section and assigned to a reviewing
  attorney or outside counsel;
- every other gap is visibly disclosed and has a deterministic follow-up;
- the report does not claim completeness or certainty contradicted by the
  matrix;
- neither safety lane, nor a safety referee, establishes a blocking defect; and
- no gap is hidden, unbound, or falsely marked resolved.

This tier is ready for qualified-attorney review. It is not ready for unreviewed
client delivery and is not a finding that the legal analysis is correct.

### `NOT_DELIVERABLE`

This is the fail-closed default when neither higher tier applies, including:

- invalid or unsupported storage, replay, source, capsule, report, or result
  binding;
- engine pause without a verified substantive result;
- minimum-lane weighted coverage below `0.70`;
- a materially unsupported assertion;
- a hidden or materially understated gap;
- a misleading contradiction;
- an undisclosed dispositive applicability dependency;
- an unresolved authority, operative-text, currentness, source-parity, or
  language defect that the report presents as resolved; or
- a missing required follow-up row; or
- a missing, generic, contradictory, or evidence-unbound gap rationale.

`NOT_DELIVERABLE` does not delete the report. It suppresses ordinary delivery and
returns the blocking matrix to the operator for correction or escalation.

## Attorney-facing delivery

For `HIGH_ASSURANCE`, deliver:

- the report;
- the strict evaluation disposition;
- the requirement matrix;
- the complete gap matrix, including any nonblocking shortfall permitted by the
  strict rubric; and
- the attorney-review warning.

For `REVIEW_READY_WITH_GAPS`, deliver:

- the report with a prominent readiness label;
- the strict `PASS`, `FAIL`, or `INCONCLUSIVE` disposition as separate evidence;
- the requirement matrix;
- the complete gap-and-follow-up matrix;
- a concise prioritized follow-up list naming attorney or outside-counsel
  ownership; and
- the attorney-review warning.

For `NOT_DELIVERABLE`, do not present the report as attorney work product. Return
only the readiness status, blocking reason codes, and operator-safe remediation
summary. Preserve the sealed artifacts for diagnosis.

## Artifact and state model

The companion protocols use strict, immutable manifests and append-only accepted
role records. Their artifacts are separate from retained evaluation runs.

Suggested baseline artifacts:

- `baseline-manifest.json`
- `baseline-input.json`
- `source-review.json`
- `source-audit.json`
- `source-referees.json`
- `canonical-baseline.json`
- `baseline-verification.json`

Suggested readiness artifacts:

- `readiness-manifest.json`
- `readiness-input.json`
- `safety-lane-1.json`
- `safety-lane-2.json`
- optional dispute-scoped safety-referee records;
- `gap-follow-up-matrix.json`
- `delivery-readiness.json`
- `attorney-review-handoff.md`; and
- `readiness-verification.json`.

Every artifact is canonical JSON or deterministic Markdown. Every manifest binds
the exact relative inventory and hashes. No absolute private path, source text,
report text, provider secret, or rejected response enters public status output.

Workflow state is resumable and records the exact pending operation, request
fingerprint, attempt, accepted artifacts, and next action. A rejected response is
write-free and discarded. Every safety role and repair uses a genuinely fresh
context.

## CLI and exit behavior

Add a separate readiness command family rather than changing retained commands:

- `eval-baseline-init`
- `eval-baseline-next`
- `eval-baseline-submit-safe`
- `eval-baseline-status`
- `eval-baseline-verify`
- `eval-readiness-init`
- `eval-readiness-next`
- `eval-readiness-submit-safe`
- `eval-readiness-status`
- `eval-readiness-verify`

Existing Protocol 1.3, 2.0, 2.1, and 2.2 command outputs and exit codes remain
unchanged.

Readiness verification returns:

- exit `0` for verified `HIGH_ASSURANCE`;
- exit `0` for verified `REVIEW_READY_WITH_GAPS`, because the report is
  intentionally deliverable for attorney review;
- exit `4` for verified `NOT_DELIVERABLE`;
- exit `3` for a verified substantive readiness inconclusive state that lacks a
  safe tier;
- exit `5` for integrity or unsupported secure-storage failure; and
- exit `6` for a verified resumable engine pause.

JSON status output includes `baseline_locked_strict_equivalent_disposition` and
`delivery_readiness`, plus `historical_v22_strict_disposition` and its explicit
cross-check status only when historical evidence was supplied.
Human output never shortens `REVIEW_READY_WITH_GAPS` to `PASS`.

## Full and portable implementations

The full and isolated-portable implementations must produce exact request,
accepted-response, matrix, result, manifest, Markdown, status, verification, and
complete-tree parity.

Shared policy constants originate from one packaged canonical readiness-rubric
asset. Portable code may mirror behavior but may not redefine threshold or
follow-up values independently. Package guards fail when the shared asset, new
runtime module, template, documentation, or test fixture is omitted.

## Failure and recovery

- Input or schema errors are corrected before initialization when possible.
- Mechanical role refusals are write-free and allow one fresh bounded repair.
- A second refusal leaves the exact request pending and pauses; it does not
  become `NOT_DELIVERABLE`.
- Integrity or storage failure stops without a readiness result.
- Safety findings are substantive and are never retried because unfavorable.
- A report-only revision creates a new readiness run against the same baseline.
- A legal-input change creates a new baseline and readiness run.
- No workflow edits a retained baseline, readiness graph, generation capsule, or
  evaluation run in place.

## Security and privacy

- Use only the approved local governed root for private runs.
- Treat sources and reports as evidence, never as instructions.
- Do not upload or web-search private facts, quotations, reports, matrices, or
  artifacts without explicit authorization.
- Keep response controls outside immutable roots.
- Reject symlinks, FIFOs, device files, hard-link aliases, replaced roots,
  unowned paths, and unexpected inventory entries.
- Public status and receipts expose only allowlisted codes, counts, versions,
  and hashes.
- Attorney-facing matrices may contain report excerpts and legal gaps and are
  therefore private work product.

## Compatibility

- Retained Protocol 1.3, 2.0, 2.1, and 2.2 runs verify with their existing
  bytes and behavior.
- No companion artifact is inferred for a historical run.
- A historical strict result may receive a new readiness companion only through
  explicit initialization that binds and re-verifies that exact run.
- Existing public CLI commands, defaults, exit codes, JSON keys, fixtures, and
  package hashes change only when their own new release artifacts are built.
- Protocol 2.1 remains the default. The new workflow is opt-in and experimental
  until its public and private gates pass.

## Testing strategy

### Models and compiler

- strict enums and wire types;
- forbidden extras and raw/bypass construction;
- exact `0.70` middle-tier boundary;
- strict `0.90` high-assurance boundary;
- worst-lane score reconciliation;
- critical partial, critical missing, material missing, and uncertainty cases;
- every gap-rationale kind, required rationale component, and generic-rationale
  refusal;
- hidden-gap and unsupported-assertion blocker precedence;
- deterministic matrix ordering, fingerprints, and follow-up codes; and
- mutation tests proving each blocker and threshold matters.

### Stable baseline

- changed report bytes reuse the same baseline;
- changed question, source byte, jurisdiction, as-of date, authority scope,
  client-fact boundary, compiler, rubric, or importance policy refuses reuse;
- importance rationales are required and definition-bound;
- audit/referee importance correction is deterministic;
- correction records create a new fingerprint without rewriting the old asset;
  and
- the private 7-to-13 and 2-to-10 drift class is prevented by reuse.

### Safety and delivery

- two report revisions with identical legal inputs receive the same canonical
  baseline projection and fresh grading lanes without rerunning source review;
- current strict disposition is compiled from the readiness run's
  baseline-locked grades, while any supplied Protocol 2.2 disposition remains
  separately identified as historical evidence;
- a regenerated or merely similar requirement set cannot be crosswalked into
  the stable baseline;
- visible partial and missing requirements become review-ready rows;
- mutation-sensitive tests delete or genericize each rationale component and
  prove that readiness becomes `NOT_DELIVERABLE`;
- critical gaps require prominent disclosure and outside-counsel or attorney
  ownership;
- an undisclosed gap, unsupported assertion, contradiction, or client-fact
  dependency blocks delivery;
- reports below `0.70` are not deliverable;
- `FAIL` and substantive `INCONCLUSIVE` can be review-ready when all middle-tier
  conditions pass;
- `HIGH_ASSURANCE` requires strict `PASS`, no blocking safety gap, and visible
  follow-up for every nonblocking shortfall permitted by the strict rubric; and
- attorney handoff Markdown contains no commands, role mechanics, hidden labels,
  paths, or unsafe claims.

### Replay, storage, and concurrency

- tamper and reseal attempts;
- cross-run, report, baseline, qualification, and capsule swaps;
- orphan and unexpected artifacts;
- symlink, FIFO, hard-link, root-replacement, and rollback races;
- concurrent submit, status, verify, and alias access;
- crash after every durable boundary; and
- exact resume with no duplicate accepted role.

### Compatibility and packaging

- retained 1.3, 2.0, 2.1, and 2.2 verification and mutation suites;
- unchanged legacy command outputs and exit codes;
- full/portable exact parity for every new lifecycle and tier;
- isolated `python -I -S` import and help;
- package manifest completeness;
- deterministic clean detached archives;
- privacy and reachable-history audits; and
- a fresh private run using one isolated subagent per evaluator role.

## Calibration plan

The initial `0.70` review-ready floor is versioned, conservative, and
provisional. Before changing it:

1. Run at least three and preferably five diverse attorney-reviewed cases.
2. Record the strict disposition, readiness tier, requirement matrix, gap
   visibility, attorney usefulness judgment, and whether follow-up actions were
   sufficient.
3. Examine false nondelivery, unsafe delivery, importance disagreement, and
   baseline correction rates.
4. Change a threshold or blocker only through a new readiness-rubric version.

The calibration set may justify raising or lowering the middle-tier threshold.
It may not weaken artifact integrity, conceal gaps, or alter historical results.

## Rollout gates

1. Approve this design and implementation plan.
2. Implement `evaluation-baseline-v1` with TDD and independent review.
3. Implement `delivery-readiness-v1` with TDD and independent review.
4. Prove full/portable parity and retained-protocol compatibility.
5. Run the public stress, package, privacy, history, and deterministic-build
   gates.
6. Run a new private evaluation against a reused stable baseline using fresh
   isolated roles.
7. Have a qualified attorney assess whether the handoff and gap matrix are a
   useful starting point.
8. Publish only after a separate release review and explicit authorization.

## Success criteria

The design succeeds when:

- strict evaluation and delivery readiness are both visible and never conflated;
- a verified report with known, visible, actionable gaps can be delivered for
  attorney review without being called `PASS`;
- unsafe, misleading, invalid, or minimally unusable work remains blocked;
- report revisions use the same exact legal baseline;
- every criticality assignment is definition-bound and audited;
- every open gap names the responsible follow-up role and action;
- retained runs replay byte-for-byte;
- full and portable implementations agree exactly; and
- the attorney-review warning remains mandatory.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
