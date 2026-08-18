# Publication Readiness and Atomic Coverage V2 Design

**Date:** 2026-08-14
**Status:** Approved for implementation planning

## Goal

Produce a bounded release-candidate path for Regulatory Harvest. The tool is
publication-ready only after three qualified locked cases each produce an
absolute Regulatory Harvest `PASS`, with exact-evidence precision, capsule
integrity, and terminal replay intact.

This iteration must address two different failure classes without allowing one
to influence the other:

1. evaluation reliability defects that prevent a valid substantive result; and
2. generation defects that compress or omit material legal propositions,
   qualifications, and trigger-to-consequence relationships.

The work stops at explicit gates. It does not continue through unbounded
locked-suite retries or private-result-driven tuning.

## Current boundary

The existing `proposition-coverage-v1` contract materially improves source
accounting. It requires every prepared source unit and provision lead to receive
a disposition and verifies exact evidence and visible brief bindings. It does
not establish that a unit was decomposed into every material legal proposition,
that every qualification was preserved, or that related triggers and
consequences remain connected in the report.

The evaluator also preserves run integrity when a response is invalid, but its
current preflight surface can collapse distinct, repairable semantic defects
into one generic error. External shell sequencing can therefore make unnecessary
submission attempts or consume repeated fresh contexts without telling the role
what mechanical contract it violated.

These are separate systems. Evaluation reliability changes may not alter report
generation or scoring. Generation-depth changes may not weaken admission,
grading, or evaluator invariants.

## Scope

### Evaluation reliability

- Qualify and version locked cases before report generation.
- Preserve prior cases and results byte-for-byte.
- Add safe operation-specific preflight diagnostics.
- Add a guarded validate-and-submit transition that cannot mutate a run after a
  failed preflight.
- Enforce bounded, explicit response-repair limits.
- Preserve full and portable runtime parity and replay verification.

### Generation depth

- Add a new `proposition-coverage-v2` contract for newly prepared matters.
- Preserve read and replay compatibility for v1 matters.
- Require source-to-atom and atom-to-report closure.
- Represent material qualifications and legal relationships explicitly.
- Keep the attorney-facing output a natural regulation-centered memo.

### Release qualification

- Run synthetic and public-safe verification first.
- Run one private substantive case as the initial release gate.
- Run the complete three-case suite once only after that case passes.
- Prepare publication artifacts only after every release gate passes.

## Non-goals

- No publication, push, pull request, or public release without separate user
  authorization.
- No private source packet, evaluator ledger, comparator report, grade,
  response, score, path, mapping, or answer text enters public Git.
- No scoring-threshold reduction, admission bypass, or special case keyed to a
  private benchmark.
- No deterministic attempt to decide substantive legal meaning or materiality.
- No token-by-token source annotation, fixed memo length, or database-style
  attorney report.
- No migration or rewriting of completed v1 bundles or evaluation histories.
- No embedded model API, storage service, n8n workflow, or SurrealDB dependency.

## Design principles

1. **Separate harness validity from product quality.** A case or response that
   cannot produce a valid evaluation is repaired as evaluation infrastructure;
   it is not evidence for a generation change.
2. **Accountability without artificial certainty.** Every review target must be
   dispositioned, but `gap`, `not_present`, and reasoned `not_material` remain
   valid outcomes.
3. **Atomic legal treatment.** A broad source-unit reference cannot by itself
   establish coverage of every rule, exception, deadline, route, or consequence
   within that unit.
4. **Relationship preservation.** The internal representation and visible brief
   must retain material links between rules and their qualifiers, exceptions,
   deadlines, enforcement routes, remedies, penalties, and appeals.
5. **Flexible presentation.** Related atoms may share a paragraph, item, or row
   when their identities and relationships remain visibly bound.
6. **Portable parity.** Full and dependency-free runtimes produce the same
   contracts, diagnostics, canonical bytes, hashes, and decisions.
7. **Finite iteration.** A failed substantive gate ends the iteration and
   returns the remaining defect for a new approved design; it does not trigger
   another automatic redesign or suite run.

## Considered approaches

### Continue tuning against the full locked suite

This produces more outcome data, but it is slow, entangles harness failures with
report failures, and creates an unacceptable risk of private benchmark
overfitting. Rejected.

### Publish the current build as a caveated beta

This is the fastest route to distribution, but it conflicts with the approved
publication gate for a legal research tool. Rejected.

### Bounded release-candidate cycle

Repair evaluator reliability with synthetic tests, implement a generic atomic
coverage contract, run one substantive gate, and run one complete suite only
after that gate passes. This is the selected approach.

## Architecture overview

The release-candidate path has four ordered boundaries:

1. **Case readiness:** a source-only admission record qualifies each versioned
   locked case before candidate generation.
2. **Atomic generation:** `proposition-coverage-v2` reconciles complete source
   review, rule atoms, exact claims, relationships, and visible brief units.
3. **Guarded evaluation:** operation-specific response validation and an atomic
   guarded submission transition produce replay-verifiable terminal results.
4. **Release decision:** the staged private gate and complete suite decide
   whether publication preparation may begin.

Evaluation artifacts never become generation inputs. Generation artifacts may
enter evaluation only through the existing verified capsule boundary.

## Evaluation reliability design

### Versioned case qualification

Before generating a candidate, the evaluation controller performs a source-only
readiness pass for each case. It confirms the existing admission dimensions:

- authority alignment;
- operative text;
- currentness evidence for the declared as-of date;
- language resolution; and
- source parity.

An unready case is not silently changed and is not used for generation. The
existing case and its history remain immutable. A corrected case receives a new
version and a new source-record fingerprint. Any added currentness material must
be public primary authority selected independently of candidate or comparator
reports. Once qualified, the new case bytes are frozen for the complete
release-candidate cycle.

Case qualification does not guarantee a candidate `PASS`. It establishes only
that the authority record is fit to score.

### Safe preflight diagnostics

Preflight continues to use the exact submit transition without writing run
bytes. On a non-integrity semantic failure, it returns a bounded diagnostic that
identifies the mechanical contract class, such as:

- incomplete response;
- insufficient audit rationale;
- invalid action cardinality;
- unknown target or source identifier;
- invalid exact-source binding;
- malformed proposed entry; or
- request-envelope mismatch.

Diagnostics may include only identifiers already supplied by the pending packet
or response. They must not expose sealed mappings, report identities, private
source text, expected legal conclusions, or later-phase artifacts. Full and
portable runtimes must return byte-identical diagnostic objects.

### Guarded validation and submission

Add one controller-facing operation that:

1. verifies the pending request and run integrity;
2. validates the complete response using the exact transition;
3. returns the safe preflight result without mutation when validation fails;
4. commits the response only when validation succeeds; and
5. returns the resulting pending or terminal state.

This eliminates shell-chain control flow between a successful preflight and
submission. Existing read-only preflight and explicit submit operations remain
available for compatibility, and explicit submit remains independently
fail-closed.

### Bounded response repair

The skill constructs canonical outer envelopes whenever possible so the model
supplies only the role judgment. A role receives:

- one initial response;
- at most two fresh-context mechanical repairs; and
- only the current request plus the safe preflight diagnostic during repair.

The same diagnostic class appearing twice ends the role immediately. Three
total attempts is the absolute maximum. A substantive grade or legal judgment
is never retried merely because it is unfavorable. Integrity failure stops the
case and suite.

## Proposition coverage v2

### Contract selection and compatibility

Newly prepared matters declare `proposition-coverage-v2`. The dossier identifies
the matching inventory and contract versions. V1 remains parseable and uses its
unchanged reconciliation branch so completed bundles and replay fingerprints do
not change.

There is no implicit upgrade. A v1 draft submitted against a v2 dossier returns
a bounded contract-mismatch diagnostic.

### Layer 1: source-unit review

Every required source unit receives one `unit_review` record. Each record checks
these loss-prone dimensions:

1. authority identity, status, and timing;
2. actors, scope, exclusions, and covered activities;
3. definitions and defined categories;
4. duties, rights, and prohibitions;
5. triggers and thresholds;
6. conditions, exceptions, and defenses;
7. deadlines, transitions, and recurring timing;
8. enforcement authorities, routes, remedies, and consequences; and
9. cross-references and upstream or downstream dependencies.

Each dimension uses exactly one disposition:

- `mapped`, with one or more atom identifiers;
- `not_present`;
- `gap`, with source-tied gap codes; or
- `not_material`, with a concrete rationale.

The review does not classify every token. It proves that each complete structural
unit was considered across the semantic dimensions most likely to be lost.
Multiple units may map to one cross-reference-dependent atom, and one dense unit
may map to many atoms.

### Layer 2: atomic rule graph

Each covered `rule_atom` represents one legal proposition. Its controlled fields
include:

- atom identifier and source target identifiers;
- category and proposition type;
- materiality and a concrete omission-consequence rationale;
- actor, modality, operative action, and object when applicable;
- trigger, threshold, timing, condition, exception, authority, route, and
  consequence when applicable;
- source-supported claim identifiers; and
- typed relationships to other atoms.

The schema uses category-specific requirements rather than requiring every
field on every atom. For example, a definition needs a defined term and meaning,
not an enforcement route. A gap is preferable to an invented field.

Material relationship types include:

- `qualifies`;
- `exception_to`;
- `deadline_for`;
- `enforces`;
- `triggered_by`;
- `consequence_of`;
- `appeals_from`; and
- `defines`.

The deterministic validator enforces relationship identities and category
cardinality. Exceptions must identify the rule they limit; deadlines must
identify the governed rule; enforcement routes must identify an authority and
regulated rule; and remedies or penalties must identify both their trigger and
consequence.

Atomicity is a drafting and validation boundary, not a grammatical word rule.
The host must split independent operative actions, rights, exceptions, and
consequences into separate atoms. Related qualifications may remain fields on a
single atom when they do not create an independent legal proposition.

### Layer 3: exact evidence and visible binding

Every covered atom binds one or more existing `source_supported` claims. Their
resolved exact citations must overlap all prepared units and leads assigned to
the atom. Every stated material element must be supported by at least one of the
atom's claims.

Every critical and material atom must appear in visible `legal_analysis`. A
supporting atom may be consolidated when it is needed to understand a visible
rule, relationship, or limitation. Brief paragraphs, individual list items, and
table rows gain atom and relationship bindings.

Several related atoms may share one visible unit. The visible unit must bind all
included atom identifiers, and each declared relationship must bind claims from
both endpoints. This permits coherent prose while preventing a penalty,
exception, or deadline from appearing detached from the rule it modifies.

`Key Requirements` remains law-facing. `Implementation Workplan` remains
application-facing. The atom ledger does not appear as a database view in the
attorney report.

### V2 coverage artifact

`coverage-review.json` advances to a new schema version for v2 matters and
contains:

- contract and inventory versions;
- deterministic results for every unit review, atom, and relationship;
- counts by disposition, category, proposition type, and materiality;
- unresolved identifiers and bounded diagnostics; and
- one canonical coverage-review hash.

The audit and sealed bundle retain the atom graph for verification. The report
contains only the rendered legal analysis and ordinary source markers.

### V2 blocking diagnostics

The existing target, claim, evidence, gap, and visibility diagnostics remain.
V2 adds bounded classes for:

- unresolved source-review dimension;
- invalid or non-atomic rule row;
- missing category-required element;
- unknown, invalid, or incomplete relationship;
- unsupported stated element; and
- relationship absent from visible analysis.

Diagnostics identify public contract identifiers, never private paths or
evaluator state.

## Flexibility limits

V2 is strict about accounting and flexible about legal presentation:

- It does not require one paragraph per atom.
- It permits multi-unit atoms and multiple atoms per unit.
- It permits explicit gaps and honest `not_present` or `not_material`
  dispositions.
- It applies fields and relationships only when relevant to the atom category.
- It does not prescribe report length or optional headings.
- It does not deterministically decide the best legal interpretation or the
  persuasiveness of a materiality rationale.
- It does not require certainty when the retained authority cannot establish an
  answer.

The normal user still supplies a legal question and sources and receives a
report. The skill owns the internal review, atom graph, repair loop, and
validation artifacts.

## Data flow

For a new v2 matter:

1. `prepare` normalizes the retained sources and emits source units and complete
   provision leads.
2. The host reads every successful source and authors unit reviews and rule
   atoms before report prose.
3. A completeness challenge checks qualifications, cross-references,
   relationships, and materiality decisions.
4. The host creates exact source-supported claims and the regulation-centered
   brief.
5. `finalize` validates unit review, atoms, evidence, relationships, gaps, and
   visible bindings.
6. Finite diagnostics return `review-required`; the host repairs and reruns.
7. Delivery requires completed status and all evidence, proposition-coverage,
   and provision-recall gates to be true.

For release evaluation, the completed report then enters a fresh verified
generation capsule and the independent attorney-evaluation workflow.

## Error handling

- A missing or mismatched v2 contract fails closed with a bounded diagnostic.
- A malformed unit review, atom, or relationship never raises an unbounded raw
  exception; full and portable runtimes return the same canonical review.
- Unknown target, atom, claim, gap, or relationship identifiers fail closed.
- A genuine source gap remains a gap and is not deleted to obtain completion.
- A failed finalization may be repaired from its finite diagnostics, but it is
  never delivered as completed.
- An unready evaluation case is versioned and requalified; admission is not
  weakened.
- A semantic evaluator result is accepted even when unfavorable. Only invalid
  transport or operation contracts receive bounded mechanical repair.

## Testing strategy

### Contract and reconciliation tests

- All nine source-review dimensions receive exactly one valid disposition.
- A coarse unit reference without required atom mappings fails.
- Independent duties in one unit require distinct atom identities.
- Material exceptions, thresholds, and defenses cannot disappear into a base
  duty atom.
- Deadlines, enforcement routes, remedies, penalties, and appeals require valid
  typed relationships.
- Exact claims support every stated material element.
- Every critical and material atom reaches visible legal analysis.
- Relationship visibility binds both endpoints while permitting consolidated
  prose.
- Valid gaps, nonmaterial navigation, cross-reference-dependent atoms, and
  non-English structural units remain supported.

### Adversarial tests

- One exact citation cannot satisfy unrelated atom elements.
- A generic consequence cannot satisfy a penalty without its trigger.
- An exception cannot point to an unknown or unrelated base rule.
- A host cannot mark a covered operative unit `not_present` merely by omitting
  its atom mappings from another dimension.
- Duplicate, cyclic where prohibited, malformed, unhashable, and
  validation-bypassing structures fail closed.
- Full and portable inputs remain unmodified.

### Evaluator and controller tests

- Source-only qualification rejects an unready case without generation.
- A corrected case receives a distinct version and fingerprint.
- Each semantic preflight class returns a safe bounded code.
- Guarded submission cannot mutate state after failed validation.
- The same response produces equivalent preflight and submit validation.
- Retry counts stop after the same defect repeats or three total attempts.
- Integrity failure stops the suite; substantive outcomes remain immutable.
- Existing terminal histories replay byte-identically.

### Packaging and regression tests

- Full and portable paths produce byte-identical new artifacts and diagnostics.
- V1 finalize and replay fixtures remain unchanged.
- Build manifests include every new runtime and instruction file.
- Clean isolated installation, full and portable help, Ruff, mypy, privacy
  audit, reproducible archive, and the full test suite pass.

## Staged release-candidate gate

The release-candidate sequence is fixed:

1. Complete public-safe implementation and verification.
2. Rebuild the skill archive reproducibly and install it locally.
3. Qualify and freeze the versioned three-case source records.
4. Generate and evaluate one fresh designated substantive case.
5. If that case receives anything other than an absolute Regulatory Harvest
   `PASS`, stop and produce one bounded defect report.
6. If it passes, run one fresh complete three-case suite.
7. Record every terminal result and verify capsule and evaluation replay.
8. Do not begin another design iteration automatically.

Mechanical evaluator failure may authorize an evaluator-only repair after its
root cause is reproduced with synthetic data. It does not authorize generation
changes or another substantive candidate run without returning to the owning
design.

## Publication acceptance

Publication preparation begins only when all of the following are true:

1. Regulatory Harvest receives an absolute `PASS` in all three qualified cases.
2. Each case has critical recall `1.0`, weighted recall at least `0.90`, and
   claim precision at least `0.95` under the unchanged public rubric.
3. Narrative and deterministic safety gates pass.
4. Generation evidence precision, proposition coverage, and provision recall
   are true.
5. Generation capsules and terminal evaluations verify and replay.
6. The full public test, type, lint, privacy, package, and reproducibility gates
   pass.
7. The installed skill matches the verified archive and passes clean smoke
   tests.
8. Release documentation accurately states limitations and qualified-attorney
   review requirements.

The comparator does not need to pass for Regulatory Harvest to satisfy its
absolute gate. No relative win can substitute for any failed Regulatory Harvest
absolute result.

After these criteria pass, the repository, release archive, checksums,
installation documentation, and draft release notes may be prepared. Public
push, repository visibility changes, and release publication require a final
separate user authorization.

## Privacy and clean-room boundary

All public implementation, fixtures, and documentation use generic logic and
synthetic or separately approved public authority. Private evaluation material
remains outside the repository and is used only through terminal, high-level
defect classes permitted by the clean-room process.

Before any publication authorization, rerun the release privacy audit against
the complete Git history and archive contents. Green tests or a passing locked
suite do not independently authorize disclosure.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
