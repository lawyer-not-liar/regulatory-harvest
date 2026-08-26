# LegalBench-RAG evaluation

Regulatory Harvest includes an optional, storage-neutral evaluator for [LegalBench-RAG](https://github.com/zeroentropy-ai/legalbenchrag). It scores exact character retrieval spans from a dataset you supply. It does not download, bundle, or redistribute LegalBench-RAG data.

LegalBench-RAG evaluates the retrieval step over its legal-contract datasets. A strong score does not establish that a system performs correct end-to-end regulatory research, finds current law, reasons accurately, or produces work that an attorney can rely on.

## Install

The evaluator is included in the base installation:

```bash
python -m pip install regulatory-harvest
```

## Obtain and review the dataset separately

Follow the official project's acquisition instructions and review the terms for LegalBench-RAG and its source datasets, including ContractNLI, CUAD, MAUD, and PrivacyQA. Harvest does not automate acceptance, acquisition, generation, or updates.

The supplied root must have this public upstream shape:

```text
dataset/
  corpus/
    ... UTF-8 text files ...
  benchmarks/
    ... JSON benchmark files ...
```

Each benchmark JSON contains `tests`. Each test has a `query`, optional `tags`, and `snippets` containing a corpus-relative `file_path` plus a half-open character `span` such as `[13, 42]`.

Harvest rejects absolute paths, parent traversal, paths outside the dataset through symlinks, non-UTF-8 text, and ranges outside the referenced Python Unicode string. Evaluation results never include corpus text or retrieved quotations.

## Prediction format

Supply UTF-8 JSON Lines with one record per case. Case IDs are deterministic: the benchmark-relative JSON path, a colon, and the zero-based test index.

```json
{"case_id":"privacy_qa.json:0","spans":[{"file_path":"privacy_qa/policy.txt","start_char":120,"end_char":184,"score":0.91}]}
```

`score` is optional and retained only while parsing; character metrics do not use ranking scores. Duplicate case IDs, unknown case IDs, unsafe paths, and out-of-range predictions are errors. A missing case is scored as retrieving no spans.

## Run

For a real dataset, acknowledge that you reviewed and accept the applicable upstream terms:

```bash
harvest eval legalbench-rag \
  --dataset /path/to/data \
  --predictions predictions.jsonl \
  --output results/legalbench-rag.json \
  --config-file retrieval-config.json \
  --accept-upstream-terms \
  --json
```

The optional configuration file must be a JSON object with scalar values. It records the exact retrieval settings associated with the predictions; Harvest does not interpret them.

The exact, fingerprinted synthetic fixture under `tests/fixtures/legalbench-mini` can run without `--accept-upstream-terms` for CI and local verification. Both its marker and its known benchmark/corpus fingerprint must match. Copying the marker or modifying the fixture produces a non-synthetic dataset and requires explicit terms acknowledgement.

## Metrics

Spans are grouped by document and overlapping or adjacent intervals are merged before scoring. This prevents duplicate hits from counting the same character more than once.

- True-positive characters are the intersection of the truth and prediction unions.
- Precision is true-positive characters divided by predicted characters.
- Recall is true-positive characters divided by truth characters.
- F1 is the harmonic mean of precision and recall.
- Micro metrics use character totals across every case.
- Macro metrics average the corresponding per-case values.

When truth and predictions are both empty, precision and recall are `1.0`. If only one side is empty, both are `0.0` for that case.

## Result artifact

The output contains:

- per-case and aggregate metrics;
- the Regulatory Harvest version;
- whether the supplied data matched the known synthetic fixture and whether terms were acknowledged;
- the caller's retrieval configuration;
- dataset-relative paths, byte sizes, and SHA-256 hashes;
- aggregate dataset and predictions fingerprints; and
- an explicit scope limitation.

It contains no dataset root path, corpus text, query answer text, retrieved text, credentials, or model output.

## Python retriever protocol

Applications can bypass JSONL by implementing the asynchronous `Retriever` protocol and calling `run_legalbench_retriever_evaluation`. The retriever receives each `LegalBenchCase` and returns `RetrievedSpan` objects. Harvest still validates every returned path and character range before scoring and writes the same text-free result schema.

## Citation and license boundary

The LegalBench-RAG paper is *LegalBench-RAG: A Benchmark for Retrieval-Augmented Generation in the Legal Domain* by Nicholas Pipitone and Ghita Houir Alami ([arXiv:2408.10343](https://arxiv.org/abs/2408.10343)). Its official code repository is MIT-licensed. Dataset and source-dataset rights are separate; consult the official repository and each source dataset rather than treating the code license as a blanket data license.

# Attorney-report evaluation

Attorney-report evaluation is a separate, closed-universe workflow. It grades a
candidate report against the supplied authority record and a sealed requirement
ledger; it is not LegalBench-RAG retrieval evaluation and does not fetch legal
sources.

## Protocol 2.2 current evaluator contract

Protocol 2.2 is explicit experimental behavior; Protocol 2.1 remains the new-run
default. Internal evaluator roles provide bounded semantic drafts rather than
persisted envelopes. Deterministic code performs safe normalization only for
mechanically provable equivalents, constructs the strict compiled response, and
submits that response through the ordinary strict preflight and atomic commit path.
Content quality is not a mechanical acceptance gate: independent audit, refereeing,
two-lane grading, and reconciliation evaluate the substance.

Source-review and source-audit fragments contain at most five new items. One driver
invocation permits an initial draft and one fresh clarification. If both drafts are
invalid, it returns exit 6 with the exact request pending and no accepted-response
write. A compatible driver can resume that same verified run without repeating an
accepted fragment. Protocol 2.2 ends only as `COMPLETED` or substantive
INCONCLUSIVE; an engine pause is nonterminal. Protocols 1.3, 2.0, and 2.1 retain
their existing replay/read-only meanings and are never upgraded in place. This
experimental evaluator makes no benchmark claim. Results still require
qualified-attorney validation before use in legal advice.

## Experimental stable evaluation baseline

The opt-in `evaluation-baseline-v1` protocol creates one report-blind,
source-derived baseline for later report revisions. Its role loop and these five
commands are attorney-hidden mechanics:

- `eval-baseline-init`
- `eval-baseline-next`
- `eval-baseline-submit-safe`
- `eval-baseline-status`
- `eval-baseline-verify`

Baseline identity binds the exact legal-input boundary: normalized source bytes and
IDs, source-record fingerprint, question, jurisdiction, as-of date, requested
authority scope, exact client-fact bytes or explicit null, admitted qualification
root and receipt, compiler contract, evaluation-rubric bytes and version,
importance-policy bytes and version, and accepted report-blind reviewer, auditor,
and referee provenance. It excludes candidate reports, report hashes, grades, and
readiness results.

The operational importance definitions are exact:

- **critical:** omission or material misstatement could change the legal bottom line,
  applicability, operative status, core duty or prohibition, enforcement exposure,
  remedy, or a dispositive deadline.
- **material:** necessary for a competent attorney briefing or implementation
  decision but not independently outcome-determinative under the current scoped
  question.
- **supporting:** useful explanatory, contextual, or implementation detail whose
  absence does not materially change the legal answer or required next action.

Every baseline proposal and every audit correction must provide a nonblank
importance rationale tied to exactly one published critical/material/supporting
definition. Missing or unreasoned tier labels are rejected rather than inferred.

A complete importance audit reviews every proposal. Every semantic or importance
disagreement goes to a source-only referee; substantive unresolved alternatives
remain contested rather than being silently resolved.

Only a verified, typed `GradeableBaselineProjectionV1` is passed to delivery
readiness. Do not regenerate the source roles for a report-only revision. Do not
require a Protocol 2.2 baseline equality check for a report-only revision. Delivery
readiness owns fresh grading for every later report revision against the verified
projection. Report-only byte changes reuse the same baseline and grade target.

Reuse is refused when any exact legal-input binding changes, including a source byte
or ID, source record, question, jurisdiction, as-of date, authority scope,
client-fact boundary, qualification, compiler, rubric, or importance policy.
Corrections require attorney approval, create a new sibling baseline, link to the
verified prior baseline, and leave all prior bytes immutable.

Resume only the exact pending request from a verified run and never repeat an
accepted role. Exit `0` means the requested baseline operation succeeded; exit
`2` means invalid input or response; exit `5` means integrity verification
failed; exit `6` means the engine paused with the exact request still pending.

Treat source and baseline artifacts as private work product. Do not upload or
web-search private material without explicit authorization. Baseline verification
establishes local integrity and replay, not legal correctness, completeness,
currentness, isolation truth, attorney approval authenticity, or report quality.
This protocol is experimental and always requires qualified-attorney review.

## Experimental delivery-readiness companion

`delivery-readiness-v1` is a separate sibling graph. Protocol 2.1 remains the
default. The companion consumes a verified stable baseline; it never rebuilds that
baseline, writes into a retained run, changes a historical disposition, or authorizes
unreviewed client delivery.

The controller runs two fresh baseline-locked grading lanes, derives a
baseline-locked strict-equivalent disposition under the retained Protocol 2.2 scoring
semantics, then runs two fresh safety lanes. Any safety disagreement receives one
fresh dispute-scoped referee. A Protocol 2.2 result is optional historical cross-check
evidence only; it never supplies the fresh grades or changes the delivery tier.

The three tiers are `HIGH_ASSURANCE`, `REVIEW_READY_WITH_GAPS`, and
`NOT_DELIVERABLE`. The review-ready floor is the exact, versioned, provisional `0.70`
minimum weighted coverage across the two fresh grading lanes. A strict-equivalent
`FAIL` remains `FAIL` even when the work is review-ready. Review-ready means a
qualified attorney may use the report as a starting point; it is not authorization for
unreviewed client delivery and is not a legal-correctness finding.

Every gap row preserves the exact evidence and renders `What is missing`, `Why it
matters`, `How to resolve it`, and `Owner`. Critical shortfalls require prominent
disclosure and reviewing-attorney or outside-counsel ownership. `NOT_DELIVERABLE`
suppresses the report from the ordinary handoff but preserves sealed artifacts and
operator-safe remediation codes.

The licensed fixture root is
`tests/fixtures/attorney-readiness-v1/stable`. Its `source.txt`, selected
`report-*.md`, and relative `validation-receipt.json` seed an access-controlled
fixture work directory. The package test materializes and verifies the exact
qualification, five-requirement baseline, generation, validation, and readiness
graphs from those bytes before driving every accepted transition through the full
and isolated portable surfaces. For the `high-assurance` fixture journey, the exact
operator lifecycle after that prerequisite materialization is:

```bash
fixture_workdir=fixture-workdir/high-assurance
python3 scripts/harvest_skill.py eval-readiness-init \
  --baseline-run "$fixture_workdir/baseline-run" \
  --qualification-run "$fixture_workdir/qualification-run" \
  --generation-run "$fixture_workdir/generation-capsule" \
  --validation-receipt "$fixture_workdir/matter/validation-receipt.json" \
  --run "$fixture_workdir/readiness-run"
python3 scripts/harvest_skill.py eval-readiness-next \
  --run "$fixture_workdir/readiness-run"
python3 scripts/harvest_skill.py eval-readiness-submit-safe \
  --run "$fixture_workdir/readiness-run" \
  --response "$fixture_workdir/response.json" \
  --provider-name actual-provider --model-name actual-model \
  --judge-isolation fresh_context
python3 scripts/harvest_skill.py eval-readiness-status \
  --run "$fixture_workdir/readiness-run"
python3 scripts/harvest_skill.py eval-readiness-verify \
  --run "$fixture_workdir/readiness-run"
```

Repeat `next` and `submit-safe` until terminal. Run the same sequence with
`report-review-ready.md` and `report-not-deliverable.md`; the package test is the
reproducible assertion that their source, report, validation, request, response,
tree, tier, and handoff bytes match the licensed fixture.

`assets/attorney-delivery-readiness-input.template.json` is the canonical public
JSON-wire representation of the exact `ReadinessInputV1` contract produced by the
high-assurance fixture. Strict typed consumers rehydrate the embedded baseline
`evaluation_rubric_bytes` and `importance_policy_bytes` UTF-8 strings as bytes before
model validation, exactly as readiness artifact admission does. The response template
validates directly as `ReadinessEvaluatorResponseV1` and its operation payload.

Repeat `next` and `submit-safe` only for the exact pending request. Every fresh grade,
safety, referee, and repair role requires a genuinely fresh context. A rejected
response is write-free. Exit `0` covers verified `HIGH_ASSURANCE` and
`REVIEW_READY_WITH_GAPS`; exit `4` covers verified `NOT_DELIVERABLE`; exit `5` covers
integrity failure; and the live workflow driver uses exit `6` for a write-free pause.
Later stateless status and verification see the unchanged pending run and exit `0`.

A report revision reuses the same baseline only when `legal_input_fingerprint` is
identical. Legal-input changes require a new baseline. Before changing the `0.70`
floor, record at least three and preferably five diverse attorney-reviewed cases in
the exact nonprivate calibration schema. For every report revision, link a restricted
companion record containing both fresh grade-lane matrices and scores, the tier and
gap-matrix visibility, attorney usefulness, follow-up sufficiency, false nondelivery,
unsafe delivery, importance disagreement, baseline correction, and any optional
historical Protocol 2.2 disposition, historical comparability, and historical delta.
Across the calibration set, compute the aggregate baseline-correction rate. The exact
public JSON template remains unchanged; linked private companion records stay outside
the public repository. Any threshold, blocker, or scoring-contract change requires a
new rubric version, may not weaken integrity or silently diverge from retained
Protocol 2.2 semantics, and never rewrites historical results.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.

## Retained Protocol 2.1 reference

## Protocol 2.1 current evaluator contract

Protocol 2.1 is the default for new evaluation runs after the public verification
gate passes; it remains experimental pending the complete public release gate.
Protocol 1.3 is retained for replay and read-only verification. Protocol 2.0 is retained for replay and read-only verification. Neither supports migration or new
work. Protocol 2.1 keeps independent
`source_review` and `source_audit`. It uses source-only referee packets
(`source_referee_fragment`), one for each material dispute. A referee may accept the reviewer,
accept the auditor, or make a substantive unresolved judgment; unresolved preserves
both alternatives as a contested requirement instead of forcing a legal choice.

Two isolated grader lanes assess each report. Ordinary requirements are sent in
deterministic batches of at most five; contested requirements are assessed
individually. Deterministic reconciliation and outcome sensitivity then determine
whether a contested baseline is outcome-stable or changes the final disposition.

The evaluator role returns only the operation-specific object governed by the pending
request's `json_schema`. The controller supplies truthful provider/model/isolation
labels to `eval-submit-safe`; deterministic code copies the pending operation and
fingerprint and constructs the canonical seven-key envelope. The public response
template remains only a compatibility reference for full-envelope callers.

A refusal writes no run byte. Each fragment has one initial response and at most one fresh mechanical repair per fragment; a second mechanical refusal stops as
`INCONCLUSIVE_MECHANICAL` and is never relabeled substantive unresolved. `PASS`,
`FAIL`, and `INCONCLUSIVE` are
limited results under this versioned evaluation rubric. They do not establish legal
correctness, completeness, currency, applicability, or suitability for legal advice.
Requirement-level findings are the primary product, and attorney review remains
required.

## Retained Protocol 1.3 reference

The remaining ledger-repair material in this section documents retained Protocol
1.3 artifacts. It is not the contract for new runs and must not be used to mutate
or upgrade a retained run.

## Source qualification and case admission

Qualify every locked case before generating a candidate. Qualification is a
candidate-free, one-response review of the exact question, requested authorities,
and source bytes. It checks authority alignment, operative text, declared-date
currentness evidence, language resolution, and the source record that the controller
must carry forward unchanged into candidate generation and evaluation. The sealed
qualification capsule is replay-verifiable; changing any source byte requires a new
versioned case and a new qualification.

New qualification cases use schema 1.1. They require a `build_binding` containing
the exact lowercase `commit` and archive `archive_sha256`, plus
`language_treatments` whose rows identify every source exactly once and state the
actual method, rationale, and any limitation. Qualification submission uses the
complete Judge Response envelope: `provider_name`, `model_name`, and truthful
`judge_isolation` surround the source-admission judgment in `payload`.

These commit, archive, language-treatment, provider, model, and isolation values
are controller- or host-supplied, replay-sealed attestations. Replay proves that
the recorded values have not changed; it is not independent proof of repository
state, archive provenance, language competence, host isolation, provider identity,
model identity, or honest execution. Qualification schema 1.0 remains supported
for legacy replay with its unchanged case projection and raw inner judgment; do
not upgrade or rewrite a retained schema-1.0 capsule.

Qualification readiness `ADMITTED` means only that the locked source record is ready
for candidate generation. It is not a report-quality `PASS`, does not grade a report,
and does not establish that the authorities are correct or current outside the
supplied record. As a deterministic minimum for `current-law` mode, at least one
non-commentary source must carry objective currentness metadata in `version`,
`effective_date`, or `supersession`; this minimum does not itself prove that the law
is current, so the currentness judgment remains required. Failed qualification seals
`CASE_INVALID` and stops before generation.

Qualification, generation, and evaluation remain separate local artifact graphs.
The controller must require successful qualification replay, then verify that the
generation input and later evaluation case use the exact same question and source
bytes. `eval-init` does not consume a qualification receipt or qualification root and
does not create a cryptographic cross-capsule binding. Evaluation admission separately
checks each candidate's generation provenance against the source record in the
evaluation case. An invalid or unreconcilable grading process is `INCONCLUSIVE`.

## Judge protocol

The public Python extension point is the provider-neutral
`AttorneyEvaluationJudge` protocol. The package CLI exposes only a clearly
identified local scripted-fixture adapter; it makes no provider or network call:

```bash
harvest eval attorney run \
  --case tests/fixtures/attorney-eval/case.json \
  --scripted-responses tests/fixtures/attorney-eval/responses/scripted-responses.json \
  --output attorney-run --json
harvest eval attorney verify --output attorney-run --json
```

The fixture adapter accepts only regular, local paths below the case fixture
directory and makes no network or provider call. Applications may use the
protocol directly. The universal skill exposes `eval-qualify-init`,
`eval-qualify-next`, `eval-qualify-submit`, `eval-qualify-status`, and
`eval-qualify-verify` for the source-only gate. After generation, its incremental
evaluation surface uses `eval-init`, `eval-next`, `eval-submit-safe`, `eval-status`,
and `eval-verify` so the host can execute one self-contained, blinded role packet at
a time. Provider selection, credentials, and any network contact remain outside the
deterministic runner.

Use `eval-submit-safe` for every evaluator response. It validates the canonical
envelope, pending-request binding, and role-specific transition before committing
the already validated transition. A refused response returns a fixed, bounded
diagnostic and writes no byte to the evaluation run. Integrity failures stop
immediately rather than becoming repair prompts.

Each role gets one initial response and at most two mechanical repairs. Every repair
must start in a genuinely fresh role context containing only the pending packet and
safe diagnostic; if a fresh context is unavailable, stop. Stop earlier when the same
diagnostic code occurs twice. Repairs may address only transport, schema, binding, or
pending-operation defects. Never retry an accepted `FAIL`, `CASE_INVALID`, or other
unfavorable substantive judgment, and never make a fourth attempt.

The source-only initial ledger audit and the repaired remaining audit intentionally
have different contracts. Initial audit findings may be qualitative: each must
identify a permitted action, materiality, and concrete source-grounded defect, but
it need not duplicate the repair role with a complete executable transaction. The
repair role must resolve every initial finding; every dispute left in
`remaining_audit` must be transaction-ready before sealing or refereeing.

## Versioned ledger repair contract

Every attorney ledger build, audit, and repair request includes the same versioned
`ledger_invariant_contract`. It is public explanatory input for the evaluator, not
a replacement for deterministic validation. The validator remains authoritative and
fail-closed. It deterministically enforces IDs and walk order, relationship targets,
exact source citations, required category fields, concrete materiality rationales,
remaining-audit request binding, and transaction-ready remaining disputes.

The contract also identifies evaluator attestations: resolving every initial
finding and saying that a complete recheck supports `complete: true` are not
independent deterministic proof. During repair, globally recheck IDs, walk order,
relationships, citations, category fields, materiality, and audit binding before
returning the complete repaired ledger. An altered or unrecognized contract is
refused; it is never silently interpreted as a new rule.

Because the contract is part of the request payload, changing its version changes
the build, audit, and repair request fingerprints. This is a new-run-only change:
start a new evaluation run for a newer contract and leave initialized or retained
runs unchanged. Replay verifies the recorded recognized contract generation and
does not rewrite historical request fingerprints.

When a guarded submission refuses a response, use only its fixed safe diagnostic
for a bounded mechanical repair in a fresh context. Discard the rejected response;
do not use its detailed content to repair the ledger or inform a later role.

Report referees still receive one anonymous dispute at a time. Entry-grade and
out-of-ledger-claim disputes carry only the graders' exact report passages. A
narrative dispute preserves those exact passages in its alternatives and expands
the anonymous context to each passage's complete enclosing Markdown H2 section.
Regulatory walk, qualification placement, requirements-workplan boundary, and
scanability use the complete anonymous report because those dimensions are
report-wide. Missing, boundary-spanning, or ambiguous section resolution also
fails safe to the complete report. Fenced pseudo-headings are not section
boundaries, and exact report bytes, including CRLF line endings, are preserved.

## Absolute and comparative outcomes

Each admitted report receives an absolute `PASS` or `FAIL`. A source-deficient
case terminates `CASE_INVALID`, and an unrecoverable judging or reconciliation
failure terminates `INCONCLUSIVE`. A one-candidate evaluation has no comparison.

Historical or otherwise external reports are evaluated in separate
one-candidate cases. Their absolute matrices may be displayed side by side, but
the evaluator does not assign a winner or tie. A formal comparison requires two
reports generated through separate verified generation capsules from the same
exact question, source bytes, client-fact bytes, and generation-instruction string.
A two-external-report or
mixed external/capsule case is rejected before run creation.

The capsule records the exact report, input, and runnable generator-artifact
bytes in a replay-verifiable local graph. Recorded provider, model, and isolation
metadata are replay-sealed attestations, not independent proof of provider
identity, model identity, host isolation, chronology, or whether a compromised
host used other context.

## Requirement-level comparison

Completed evaluations retain an evidence-level requirement matrix in
`evaluation-result.json` and render it in `evaluation-report.md`. Each row is
derived from one sealed ledger entry and includes its anonymous A/B findings,
report locations, semantic finding codes, selected rationale, and exact source
span pins. When only one report is supplied, the B fields are explicitly absent.
Aggregate recall and precision remain available under the separate **Score
Summary** heading.

The verifier replays the matrix from `legal-ledger.json` and the immutable
resolved-grade artifacts. Any changed ledger proposition, citation pin, report
finding, or rationale therefore invalidates the run even if the result and
manifest hashes were recomputed.

Persisted evaluation artifacts use schema `1.3`; retained `1.2` and older roots are
rejected as unsupported rather than silently reinterpreted. Schema 1.3 grades bind
exact report passages and out-of-ledger source evidence. The delivered result and
Markdown report also disclose aggregate judge isolation conservatively: one
`sequential_same_context` call makes the aggregate sequential; otherwise it is
`fresh_context`. Detailed per-call provenance remains in the manifest. The
host-facing `JudgeResponse` envelope remains schema `1.0`.

## Local-only artifacts

Run artifacts are local, fingerprinted, and can be verified read-only with the
package `attorney verify` command or the skill's `eval-verify` command. CLI JSON
deliberately omits source and report text. The source packet, reports, role
responses, and generation artifacts can still be sensitive and belong in an
access-controlled, non-public, non-synced directory.

## Limits of automated legal evaluation

This evaluator measures fidelity to its supplied authority record and rubric.
It does not establish that legal advice is correct, complete, applicable, or
current outside that record. Live Windows storage execution is unverified and
remains a release gate.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
