# Fully Automated Attorney Evaluation Design

**Date:** 2026-08-11
**Status:** Approved for implementation

## Goal

Replace routine human blind comparison with a fully automated, source-grounded
evaluation of Regulatory Harvest attorney reports. The evaluator must determine
whether a case is fit to score, measure each report against the governing
authority requirement by requirement, detect material legal defects, assess the
quality of the regulatory walk, and issue its own final disposition.

The evaluator produces two distinct conclusions:

1. an absolute quality disposition for each report; and
2. a blind comparative result when two reports received genuinely comparable
   evidence.

No attorney rating form, routine sampling, or human approval gate is part of the
evaluation workflow.

## Decision

Use a source-only requirement ledger, two blind report graders, and an automated
referee. Deterministic code owns case integrity, evidence checks, scoring,
thresholds, artifact validation, and final aggregation. Model judgment owns the
substantive source reading, atomic legal proposition extraction, report-to-law
comparison, and narrative assessment.

The evaluator may return `CASE_INVALID` or `INCONCLUSIVE`. Full automation means
that the system reaches and records the disposition without human intervention.
It does not require the system to manufacture a winner from inadequate evidence
or unresolved material disagreement.

## Why this architecture

### Single model judge

A single model could read the packet and both reports, then choose a winner. This
is inexpensive, but it creates anchoring, ordering, verbosity, and self-consistency
bias. It also makes a polished report appear complete without proving that each
material provision was addressed.

### Source ledger plus one grader

Building a source-derived ledger before grading makes omitted requirements
visible and separates the governing authority from either report. One grader can
still misread the source, apply the rubric inconsistently, or favor a writing
style.

### Source ledger plus blind panel and referee

The approved architecture combines:

- one source-only ledger builder;
- one source-only adversarial ledger auditor;
- two independent, identity-blind report graders;
- a referee limited to material disagreements; and
- deterministic aggregation and fail-closed gates.

This costs more model work, but it directly addresses the failure modes exposed
by formative comparison: unsupported richness, incomplete source packets,
outdated status treatment, missed requirements, and preference judgments based
on overall feel instead of a provision-by-provision comparison.

## Evaluation boundary

### Evaluation modes

Every case declares one of two modes.

`current-law` is the default for Regulatory Harvest. The case must contain the
official authority and enough version, amendment, effective-date, and
supersession evidence to evaluate the law as of the stated date.

`closed-universe` evaluates only what the supplied materials establish. The
result must state that it does not establish current law outside that universe.
The case still needs enough operative text to answer the scoped question.

The mode is fixed before the ledger builder or graders run.

### Absolute evaluation

Each report is evaluated against the source-derived ledger. A report can fail
even if it is better than the comparison report. A report can pass even when the
comparison result is a tie.

### Comparative evaluation

A comparison is valid only when both reports can fairly be judged against the
same legal and factual record. The evaluator never treats a prior report as the
answer key. A prior or legacy report is another candidate report.

Application analysis is scored only when independently preserved client facts
were supplied to both systems. Missing client facts do not invalidate an
otherwise sound comparison of the law. They make the application dimension
`NOT_APPLICABLE`.

### Benchmark independence

For `current-law` evaluation, the evaluator assembles and freezes its authority
record independently of either candidate report. Candidate citations may create
discovery leads, but they cannot establish that an authority is operative,
complete, or current. The evaluator verifies the official instrument and version
into the case envelope before grading.

For `closed-universe` evaluation, the declared common packet is the benchmark
record. The envelope fingerprints that packet separately from each candidate's
own source bundle so the evaluator can prove that both systems were judged
against the same universe.

## End-to-end workflow

### 1. Freeze the case envelope

The evaluator creates an immutable case envelope before any model judgment. It
contains:

- case identifier, evaluation mode, jurisdiction, research question, and as-of
  date;
- requested authorities and the expected type of legal instrument;
- normalized source records with exact content hashes;
- source role, quality, completeness, language, version, and relationship
  metadata;
- independently preserved client facts, if any;
- anonymous report artifacts and their hashes;
- the evaluation configuration and rubric version; and
- random A/B assignments sealed outside grader inputs.

The case fingerprint covers every field that can affect an evaluation. A changed
source, report, rubric, model response, or threshold produces a new run rather
than mutating an existing result.

### 2. Run the case-admission gate

Admission is case-specific. Global export presence or corpus-level source counts
cannot establish parity for an individual matter.

Deterministic checks validate hashes, paths, required metadata, nonempty text,
and declared source relationships. A model-assisted source audit then answers
the legal-content questions that metadata alone cannot answer.

A `current-law` case is invalid when any material condition remains true:

- the requested instrument is missing, misidentified, or unrelated to the
  research question;
- no successful primary authority supports the operative legal rules;
- the packet contains only search snippets, summaries, or isolated fragments
  where operative text is required;
- an amending instrument is supplied without the amended or consolidated text
  needed to understand the law;
- version, effective-date, amendment, repeal, or supersession evidence is too
  weak to evaluate the stated as-of date;
- the relevant authority is in a language the graders cannot reliably evaluate
  and no verified translation is present;
- a comparative report relied on material outside authority that is absent from
  the common evaluation record; or
- the two reports did not receive materially equivalent source and client-fact
  access.

A `closed-universe` case may omit external currentness research, but it remains
invalid when the supplied universe does not contain enough operative material to
answer its own question.

Admission produces `case-readiness.json` with one of:

- `ADMITTED`;
- `CASE_INVALID`; or
- `INCONCLUSIVE` when the source audit cannot resolve a material readiness fact
  after the allowed automated retry.

An invalid or inconclusive case does not enter the scoring denominator and does
not produce a comparative winner.

### 3. Build the source-only legal ledger

The ledger builder receives the admitted sources, question, jurisdiction, mode,
and as-of date. It receives no candidate report text or system identity.

It reads the complete successful source text and creates atomic ledger entries
for material propositions. Each entry records:

- stable ledger identifier and walk order;
- category: status, scope, definition, requirement, prohibition, right,
  exception, deadline, enforcement, remedy, penalty, appeal, or implementation;
- materiality: `critical`, `material`, or `supporting`;
- regulated actor or rights holder;
- legal modality and operative action;
- object, trigger, threshold, conditions, and exceptions;
- deadline or recurring timing;
- enforcing authority, route, remedy, and consequence when applicable;
- relationships to other ledger entries, such as `qualifies`, `excepts`,
  `triggers`, `enforces`, or `amends`;
- a concise legal proposition; and
- one or more exact source spans.

An entry cannot become ledger truth without exact source support. Commentary can
identify a lead or explain context, but it cannot independently establish an
operative legal rule.

The ledger also records supported negative conclusions and material gaps. It
does not convert the existing heuristic provision inventory into legal findings.
The inventory remains an inclusive omission-check index.

### 4. Audit and seal the ledger

The adversarial ledger auditor receives the same source-only record and the
proposed ledger. It checks for:

- omitted material provisions;
- combined entries that hide distinct duties or exceptions;
- requirements missing their triggers, thresholds, timing, or qualifications;
- penalties missing the triggering violation or enforcement route;
- status statements that exceed version evidence;
- commentary promoted into law;
- duplicative entries that would inflate recall; and
- immaterial provisions incorrectly marked critical.

The ledger builder receives a single structured repair opportunity. If material
ledger issues remain, an automated ledger referee resolves only the disputed
entries. Unresolved critical disagreement produces `INCONCLUSIVE`.

The sealed `legal-ledger.json` is hashed before either grader sees a report.

### 5. Run deterministic report checks

Existing Regulatory Harvest checks remain distinct from model grading. When a
candidate is a Regulatory Harvest bundle, the evaluator imports its validation
receipt, bundle hash, coverage review, exact citation spans, source hashes, and
brief structure profile.

Blocking deterministic failures include:

- mismatched or fabricated quotations;
- missing citation targets;
- material source-supported claims without citations;
- unresolved priority provision leads;
- missing canonical coverage dimensions;
- invalid matter title or canonical section structure;
- source-framed legal analysis where direct legal voice is required;
- requirements content placed in the implementation workplan or application
  instructions placed in Key Requirements; and
- an invalid or mismatched bundle hash.

Reports from other systems may not have a native bundle. The evaluator extracts
a report claim inventory and checks every legal claim against the common source
record. Missing native receipts are recorded as unavailable controls, not
automatically treated as defects.

### 6. Grade each anonymous report independently

Two graders evaluate each report in separate role executions. Each grader sees:

- the sealed legal ledger;
- the anonymous report;
- exact source spans needed to verify a ledger or report claim;
- the evaluation rubric; and
- deterministic findings relevant to that report.

The grader does not see the other report, the A/B answer key, prior preferences,
or the first grader's result.

For every ledger entry, each grader assigns one disposition:

- `COMPLETE`: accurate and materially complete treatment;
- `PARTIAL`: correct core rule with a material qualification, trigger,
  exception, deadline, route, or consequence omitted;
- `MISSING`: no meaningful treatment;
- `OVERSTATED`: the report expands the supported rule;
- `CONTRADICTED`: the report conflicts with the authority;
- `UNSUPPORTED`: the report states a material proposition absent from the
  evaluation record; or
- `NOT_APPLICABLE`: the entry is outside the scoped question.

The structured grade also carries a closed set of semantic finding codes where
a disposition or narrative score alone would erase the attorney-relevant
reason for the defect.  The v1 findings are:

- `CRITICAL_LEDGER_ENTRY_MISSING`;
- `MATERIAL_EXCEPTION_MISSING`;
- `CONSEQUENCE_TRIGGER_DETACHED`; and
- `KEY_REQUIREMENTS_ACTION_PLAN`.

Each finding is attached to the exact ledger entry or narrative dimension that
supports it and is validated against that structured context.  Unknown,
duplicate, or context-inconsistent findings invalidate the grade.  A finding
disagreement between the two graders is outcome-relevant audit evidence and
must be reconciled; it may not be discarded merely because the numeric score
or coverage disposition agrees.  The selected findings survive immutable
replay and are published as report issue codes.  They explain an existing
rubric or safety failure but do not create a second, hidden pass/fail rubric.

Each disposition includes a concise rationale, report location, cited ledger
identifiers, and severity. Graders also inventory material report claims that do
not map to a ledger entry so polished additions cannot escape review.

### 7. Grade the attorney-facing regulatory walk

Each grader applies a separate four-point rubric to these composition qualities:

- Executive Summary states the regulation's practical legal effect directly;
- the report walks status, scope, definitions, requirements, exceptions,
  enforcement, penalties, timing, and implementation in a coherent order;
- Key Requirements presents the law rather than an action plan;
- penalties connect violation, consequence, enforcing authority, and route;
- material qualifications are integrated where the reader needs them;
- Implementation Workplan remains distinct from the legal-rule account;
- limitations explain the actual evidentiary boundary; and
- headings and prose allow an attorney to understand the regulation quickly.

Length, number of headings, and rhetorical confidence are never independent
positive signals. Narrative scoring cannot cure a material legal error or a
missing critical provision.

### 8. Resolve disagreements automatically

The deterministic aggregator identifies grader disagreements that could change:

- a critical-error gate;
- the absolute pass threshold;
- the comparative winner; or
- the overall confidence level.

The referee receives only the disputed ledger entries, relevant source spans,
the anonymous report passages, and both rationales. It does not receive system
identity or undisputed scores. The referee selects one disposition and explains
the source-grounded reason.

Invalid structured output receives one automated retry. A second invalid result
produces `INCONCLUSIVE` for the affected report or case. The evaluator does not
silently drop an ungradable dimension.

### 9. Aggregate absolute scores

Materiality weights are versioned with the rubric:

- `critical`: 5;
- `material`: 3; and
- `supporting`: 1.

Recall credit is:

- `COMPLETE`: 1.0;
- `PARTIAL`: 0.5; and
- `MISSING`: 0.0.

`OVERSTATED`, `CONTRADICTED`, and `UNSUPPORTED` receive no recall credit and also
count against precision. `NOT_APPLICABLE` is excluded from the denominator.

The initial `attorney-eval-v1` absolute pass requires:

- an admitted case and a sealed valid ledger;
- no critical deterministic failure;
- no contradicted critical proposition;
- no unsupported or overstated material status, obligation, deadline,
  enforcement, remedy, or penalty claim;
- 100 percent coverage of critical ledger entries;
- at least 90 percent materiality-weighted ledger recall;
- at least 95 percent material legal-claim precision; and
- an average regulatory-walk score of at least 3.0 out of 4, with no composition
  dimension below 2.

The rubric and thresholds are stored in the result. Changing them creates a new
rubric version and requires rerunning the suite.

Materiality-weighted ledger recall is the sum of each applicable ledger entry's
weight multiplied by its recall credit, divided by the total applicable ledger
weight. Material legal-claim precision is the supported weight of candidate
claims divided by the total weight of candidate claims. `COMPLETE` support
receives full precision credit, `PARTIAL` support receives half credit, and an
overstated, contradicted, unsupported, or fabricated claim receives zero credit.
The claim inventory and ledger-entry inventory remain separate so a missing rule
reduces recall while an invented rule reduces precision.

Absolute dispositions are:

- `PASS`: every blocking condition and threshold passes;
- `FAIL`: a blocking condition or threshold fails;
- `INCONCLUSIVE`: material automated adjudication could not be completed; or
- `CASE_INVALID`: the case never passed admission.

### 10. Aggregate the comparative result

The comparative score combines:

- 45 percent materiality-weighted ledger recall;
- 25 percent material legal-claim precision; and
- 30 percent normalized regulatory-walk quality.

Critical gates remain outside the weighted score. The weights rank reports only
after the safety rules have been applied.

A report with a critical legal defect cannot win over a report without one,
regardless of its narrative score. If both reports have critical defects, the
comparative result may be `NEITHER`.

After critical gates, a normalized difference of five percentage points or more
produces a win. A smaller difference produces `TIE`. The answer key is revealed
only after aggregation maps the anonymous result back to system names.

Comparative outcomes are:

- `REGULATORY_HARVEST_WIN`;
- `COMPARATOR_WIN`;
- `TIE`;
- `NEITHER`;
- `INCONCLUSIVE`; or
- `CASE_INVALID`.

## Judge execution and portability

### Provider-neutral judge protocol

The Python package adds an `AttorneyEvaluationJudge` protocol with strict
request and response models for these operations:

- `admit_case`;
- `build_ledger`;
- `audit_ledger`;
- `repair_ledger`;
- `grade_report`; and
- `referee`.

Applications may supply any compatible model provider. The deterministic engine
does not require a particular vendor, API key, model SDK, search provider,
database, or orchestration system.

### Skill-host execution

The universal skill provides the default no-setup path for Codex and Claude
Desktop. The bundled Python engine creates strict, blinded role packets. The host
agent executes each role, writes the required JSON response, and invokes the
engine to validate and aggregate it. The internal workflow has multiple phases,
but the user makes one request and performs no rating step.

Where the host can isolate model calls, each grader runs in a fresh context.
Where it cannot, the result records `judge_isolation: sequential_same_context`.
The source ledger is still sealed before report text is introduced, report
identity remains hidden, and the referee receives only disputes.

### Portable implementation

The self-contained skill ZIP includes a dependency-free attorney-evaluation
runner. It uses the same schema, issue codes, weights, thresholds, fingerprints,
and aggregation rules as the package implementation. Full and portable paths
must produce byte-equivalent deterministic artifacts when supplied the same
validated judge responses.

LegalBench-RAG remains a separate retrieval benchmark. Its metrics are not
combined with the attorney-evaluation score.

## Artifacts

Each run writes an immutable directory containing:

- `case-envelope.json`;
- `case-readiness.json`;
- `legal-ledger.proposed.json`;
- `legal-ledger-audit.json`;
- `legal-ledger.json`;
- `grader-a-report-a.json` and corresponding anonymous grader artifacts;
- `grader-b-report-a.json` and corresponding anonymous grader artifacts;
- `referee.json`, when required;
- `deterministic-checks.json`;
- `evaluation-result.json`;
- `evaluation-report.md`; and
- `run-manifest.json` with source, report, prompt, rubric, model, response, and
  artifact fingerprints.

`evaluation-report.md` leads with the absolute disposition, comparative result,
and case-readiness status. It then provides the requirement-by-requirement
matrix, critical defects, unsupported claims, omissions, narrative rubric,
confidence, and exact reasons for any invalid or inconclusive result.

Artifacts are written atomically. Existing completed run artifacts are never
overwritten. Resuming a run verifies every existing hash before continuing.

## Private benchmark and public release boundary

The private evaluator remains under the local workshop. It owns:

- retained source corpora;
- prior and legacy analyses;
- client facts;
- report-to-system mappings;
- sealed answer keys;
- completed human review state;
- private calibration expectations; and
- private automated run artifacts.

The public repository may contain only:

- generic evaluation models and deterministic aggregation;
- provider-neutral judge protocols;
- public-safe prompts and rubrics;
- synthetic source and report fixtures;
- mutation-test generators; and
- documentation that contains no private matter identity, source text, report
  text, client fact, rating, or mapping.

The public release audit scans for private paths, case identifiers, report
phrases, answer-key material, and retained source hashes. No evaluation artifact
is uploaded, telemetered, or published automatically.

## Automated evaluator regression

The evaluator must test itself before it is trusted to evaluate the product.

### Public synthetic mutations

Starting from a correct public-safe regulation fixture, tests create controlled
defects:

- remove a critical duty;
- omit a material exception;
- change a deadline;
- invent a penalty;
- detach a consequence from its triggering violation;
- state an amended rule as pending after it took effect;
- swap in the wrong instrument;
- supply fragments instead of operative text;
- supply foreign-language text without an admissible translation;
- convert Key Requirements into an implementation checklist; and
- add fluent but unsupported legal prose.

Each mutation has an expected ledger disposition, critical gate, score effect,
and final result.

### Locked private fixtures

Completed formative comparisons remain immutable. Their abstract adjudicated
outcomes may serve as locked regression expectations inside the private
workshop. The evaluator must preserve the distinction between:

- a genuine substantive tie;
- a source-grounded Regulatory Harvest win over stale or unsupported treatment;
  and
- an invalid comparison caused by an inadequate common source record.

No new human calibration round is required. A disagreement with a locked fixture
is reported as evaluator drift and fails the automated regression suite until the
rubric, prompt, case admission, or expected result is explicitly versioned.

## User experience

The primary skill journey is one instruction:

> Evaluate the latest Regulatory Harvest build against the locked suite.

The skill then:

1. prepares and fingerprints fresh cases;
2. runs admission;
3. builds and audits the source-only ledger;
4. grades anonymous reports twice;
5. referees material disagreements;
6. aggregates absolute and comparative outcomes;
7. verifies all artifacts; and
8. returns a concise suite summary with paths to the detailed matrices.

There is no browser review session, report-rating sequence, reveal button, or
human score entry.

## Error handling

- Input, schema, path, or hash failures stop before model judgment.
- Case-readiness failures produce `CASE_INVALID` with stable issue codes.
- Invalid model output receives one bounded repair attempt.
- A repeated model failure produces `INCONCLUSIVE` and preserves diagnostics.
- A failed report generation is a candidate failure, not an evaluator crash.
- One invalid case does not prevent valid cases in the suite from completing.
- The suite exits nonzero when any required candidate report fails, any expected
  regression outcome drifts, or evaluator integrity checks fail.

## Non-goals

- Do not use a legacy report as legal ground truth.
- Do not infer current law from a source packet that lacks version evidence.
- Do not force every case to produce a winner.
- Do not claim that LegalBench-RAG retrieval scores establish attorney-report
  quality.
- Do not add n8n, SurrealDB, MCP, or mandatory provider dependencies.
- Do not make private evaluator material part of the release package.
- Do not alter completed human review rounds.
- Do not publish, push, merge, or contact an external service.

## Acceptance criteria

1. One skill invocation completes the evaluation without user ratings or human
   approval.
2. Admission is calculated per case and rejects an instrument mismatch, an
   extract-only packet, an unresolved language boundary, and inadequate
   version/currentness evidence.
3. The legal ledger is source-only, exact-cited, adversarially audited, and
   sealed before report grading.
4. Every material ledger entry receives a final disposition for every admitted
   report.
5. Material report claims absent from the ledger are independently checked and
   cannot gain credit through fluent prose.
6. Two blind graders and an automated referee produce a complete, validated
   adjudication or an explicit `INCONCLUSIVE` result.
7. Absolute pass/fail and comparative win/tie/loss remain separate.
8. Critical legal defects override narrative preference.
9. Full and portable paths have deterministic schema, issue-code, scoring, and
   artifact parity.
10. Synthetic mutation tests prove detection of omissions, overstatement,
    stale status, invented penalties, instrument mismatch, and language failure.
11. Locked private fixtures reproduce their adjudicated outcome classes without
    exposing private content.
12. Completed evaluation runs are immutable, resumable by hash, and free of
    network publication or telemetry.
13. The universal skill remains one self-contained release ZIP for Codex and
    Claude Desktop.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
