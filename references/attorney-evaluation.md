# Automated attorney evaluation

## Contents

- Evaluation contract
- Establish a protected physical workspace
- Qualify the locked source record
- Generate capsule-backed reports
- Understand the capsule proof boundary
- Prepare evaluation cases
- Run the blind role loop
- Handle terminal states and failures
- Deliver the result

## Evaluation contract

Complete the entire evaluation from one user request. Do not ask the user for ratings,
present a browser reviewer, or pause for a preference between reports.
The deterministic runner owns blinding, transitions, validation, aggregation,
and immutable artifacts. The host model supplies only the judgment requested in
the current role packet.

Keep the controller attorney-hidden.

- Qualify every locked case before generating a candidate.
- Use eval-submit-safe for every evaluator response.
- For each Protocol 2.1 fragment, allow one initial response and at most one fresh mechanical repair per fragment.
- Start every mechanical repair in a genuinely fresh role context.
- If a genuinely fresh repair context is unavailable, stop rather than repair in the same role context.
- Stop inconclusively after a second mechanical refusal.
- Never retry an unfavorable substantive judgment.
- Accept an unfavorable substantive result without retry.
- Verify terminal evaluation artifacts before delivery.

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

## Experimental delivery-readiness controller

When explicitly requested, initialize `delivery-readiness-v1` as a separate sibling
graph from a verified baseline, qualification capsule, generation capsule, and
completed deterministic validation receipt. Protocol 2.1 remains the default. Do not
infer a readiness companion for a retained run, change a default, or treat the result
as authorization for unreviewed client delivery.

Run two fresh baseline-locked grading lanes against the exact verified projection,
then two fresh safety lanes. Start one fresh dispute-scoped referee for each safety
disagreement. Each role and mechanical repair uses a genuinely fresh context. A
second mechanical refusal is write-free, leaves the exact request pending, and causes
the live driver to return exit `6`; it is not a substantive nondelivery result.

Keep the baseline-locked strict-equivalent disposition separate from both the optional
historical Protocol 2.2 cross-check and delivery readiness. A fresh `FAIL` remains
`FAIL`; it can coexist with `REVIEW_READY_WITH_GAPS` when the exact provisional `0.70`
minimum-lane floor and all candor, evidence, visibility, ownership, replay, and safety
gates pass. Exit `0` then means ready for qualified-attorney review, not legal
correctness. Verified `NOT_DELIVERABLE` returns exit `4` and suppresses the report as
attorney work product; integrity failure returns exit `5`.

Render every row under `What is missing`, `Why it matters`, `How to resolve it`, and
`Owner`. Never invent rationale from a score or code. A visible actionable gap is not
itself a blocker. Hidden material limitations, unsupported assertions, misleading
contradictions, unbound dispositive facts, or generic and evidence-unbound rationales
remain blocking.

Reuse the same stable baseline for a report-only revision only when
`legal_input_fingerprint` is identical. Any legal-input change requires a new
baseline. Threshold calibration requires at least three and preferably five diverse
attorney-reviewed cases and a new rubric version; keep restricted calibration results
outside the repository.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.

## Protocol 2.2 new-run contract

Protocol 2.2 is explicit experimental behavior; Protocol 2.1 remains the new-run
default. Each internal role authors a bounded semantic draft, never a persisted
envelope. Deterministic code applies safe normalization only to mechanically provable
equivalents, assigns controller-owned fields, and creates the strict compiled
response. Content quality remains the responsibility of independent source audit,
refereeing, isolated grading, and reconciliation.

Source-review and source-audit fragments contain at most five new items. A driver may
request one initial draft and one fresh clarification for the same pending fragment.
Two invalid internal drafts return exit 6 and leave the exact request pending without
an accepted-response write. Resume reuses that verified request and never repeats an
accepted fragment. Protocol 2.2 terminal outcomes are `COMPLETED` and substantive
INCONCLUSIVE; an engine pause is not an evaluation disposition. Protocols 1.3,
2.0, and 2.1 retain their existing replay/read-only contracts and are never migrated
or resumed as 2.2. This path makes no benchmark claim, and qualified-attorney
validation remains required before legal advice.

## Retained Protocol 2.1 operator reference

## Protocol 2.1 new-run contract

Protocol 2.1 is the experimental default for new evaluation runs only after the
public verification gate passes. Protocols 1.3 and 2.0 are retained for replay and
read-only verification; do not mutate, upgrade, or use them for a new run. Protocol
2.1 starts with `source_review` and `source_audit`, then issues one source-only
`source_referee_fragment` packet per material dispute. Deterministic code owns IDs,
ordering, fingerprints, hashes, scoring, aggregation, and transactions.

Each referee fragment accepts the reviewer, accepts the auditor, or records a valid
substantive unresolved judgment. An unresolved fragment preserves both supported
alternatives as a contested requirement and proceeds to grading. Two isolated grader
lanes process ordinary requirements in batches of at most five and each contested
requirement individually. Deterministic outcome sensitivity returns substantive
`INCONCLUSIVE` only when the unresolved baseline changes the result or cannot be
meaningfully graded; it does not use a raw unresolved-count threshold.

Each role returns only the operation-specific inner payload required by the pending
packet's `json_schema`. The controller, not the role, supplies truthful
provider/model/isolation metadata and deterministically constructs the seven-key
outer envelope. Use `assets/attorney-evaluation-v21-response.template.json` only as a
compatibility reference for already-authored full envelopes. A refused response is
write-free and discarded. Each Protocol 2.1 fragment gets one initial response and at
most one fresh mechanical repair per fragment.
Stop as `INCONCLUSIVE_MECHANICAL` after a second mechanical refusal. Never retry an
accepted substantive `FAIL` or `INCONCLUSIVE`.

Do not submit while a role is still writing or validating its payload. After the role
finishes, hash the exact final canonical payload for the private controller record,
then call `eval-submit-safe` with `--provider-name`, `--model-name`, and
`--judge-isolation`. The runner copies the pending operation and request fingerprint
and seals the canonical outer envelope itself. Never expose or reuse rejected payload
content in a repair role.

```bash
python3 <skill-directory>/scripts/harvest_skill.py eval-submit-safe \
  --run <run-directory> \
  --response <control-directory>/inner-payload.json \
  --provider-name <actual-provider> \
  --model-name <actual-model> \
  --judge-isolation <fresh_context-or-scripted_fixture>
```

PASS means the report satisfied this versioned evaluation rubric. It does not
establish legal correctness, completeness, currency, applicability, or advice
suitability. Requirement-level findings are the primary product, and attorney review remains required.
Protocols 1.3 and 2.0 are retained for replay and read-only verification; do not
mutate, upgrade, or use their legacy flows for a new run.

## Retained Protocol 1.3 operator reference

The remaining ledger-oriented instructions describe retained Protocol 1.3 behavior,
not the current new-run contract.

Do not expose commands, JSON, role packets, role queues, or repair mechanics
unless the user asks for technical detail.

Use `<skill-directory>/scripts/harvest_skill.py`; it selects the packaged engine
when available and the standard-library engine otherwise. Use a Python 3.11 or
newer command available on the host (`python3`, `py -3`, or an equivalent). Keep
the control directory and run directory in a user-supplied or approved
workspace. Do not write control files inside the immutable run directory.

## Establish a protected physical workspace

Before generation or evaluation, choose an access-controlled, non-synced,
non-public local directory unless the user has explicitly approved sharing. The
host AI service still processes the current role packet according to that
service's processing and retention terms and settings; a local directory does
not make a hosted model offline. Obtain explicit authorization before uploading or sharing
any source, fact, report, response, capsule, run, or derived artifact.

Resolve every input root, capsule, control directory, case root, case file,
generator artifact, report, response, and evaluation run directory to physical absolute paths
before the first generation step. Do not pass symlink aliases such
as macOS `/tmp` when its physical path is `/private/tmp`; keep using the resolved
paths for the complete journey.

Inventory the exact immutable copies needed for the journey: sources, client
facts, reports, role responses, and the runnable generator artifact. Capture only
those allowlisted files. Never capture credentials, tokens, environment files
such as `.env`, configuration files, `.git`, or unrelated tree files. Keep
control responses outside immutable capsules and runs; the runner copies and
seals only the artifacts its manifest identifies.

## Qualify the locked source record

Before generating any new candidate, freeze the common question, jurisdiction,
as-of date, requested authorities, and exact source bytes in one source-only
qualification case. Qualification contains no report or candidate text. Copy
`assets/attorney-evaluation-qualification.template.json` to the control
directory, replace every `__REPLACE__` sentinel, and use only relative source
paths beneath its input root. The template uses qualification schema 1.1. Replace
its fictional `build_binding.commit` and `build_binding.archive_sha256` values
with the exact 40-character lowercase Git commit and 64-character lowercase
SHA-256 of the archive being qualified. Populate `language_treatments` with the
method actually used, its rationale, and any material limitation; its `source_ids`
must cover every source exactly once.

The `commit`, `archive_sha256`, and `language_treatments` values are
controller-supplied, replay-sealed attestations. They bind those declarations to
the capsule and make later alteration detectable; they are not independent proof
of repository state, archive provenance, language competence, translation quality,
or what a host actually inspected.

Run this attorney-hidden order:

1. Initialize the qualification capsule:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-qualify-init \
     --case <control-directory>/qualification-case.json \
     --run <qualification-capsule-directory> \
     --nonce-hex <fresh-64-lowercase-hex>
   ```

2. Fetch `eval-qualify-next`, execute only its source-admission judgment, and
   write the complete Judge Response envelope to a control-directory response
   file. Copy `operation` and `request_fingerprint`, record the actual nonblank
   provider and model names and truthful `judge_isolation`, and put the
   schema-valid inner judgment in `payload`.
3. Submit that envelope with `eval-qualify-submit` and require
   `"accepted":true`:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-qualify-submit \
     --run <qualification-capsule-directory> \
     --response <control-directory>/qualification-response.json
   ```

4. Run `eval-qualify-verify` and require `"valid":true`. Continue only when
   the sealed receipt reports readiness `ADMITTED`. Use `eval-qualify-status`
   only to resume the capsule's recorded state.

Qualification schema 1.0 remains replay-compatible. A retained schema-1.0 capsule
uses its unchanged case projection and raw inner judgment response; replay it as
recorded rather than adding schema-1.1 fields or rewriting any artifact byte.

Qualification readiness is not a report-quality PASS. It establishes only that
the candidate-free source record is fit to use for evaluation as of the declared
date; it does not grade a report or predict an evaluation disposition. Use those
same exact qualified source bytes, question, jurisdiction, and as-of date for
generation and evaluation. Changing any source byte creates a new versioned case.
Create a new qualification capsule, candidate capsule, and evaluation run rather
than editing or reusing an earlier artifact graph.

## Generate capsule-backed reports

From one user request, perform this sequence automatically for every report that
will be newly generated, but only after the locked source record is admitted and
verified. Create a separate input root and capsule directory for each candidate.
A formal two-report comparison requires both capsules to capture the same exact
question, qualified source bytes, and client-facts bytes. Give each report a
distinct candidate identifier and fresh random 64-character lowercase
hexadecimal nonce.

1. Resolve the exact runnable generator build under evaluation and its documented
   launch command. This is the actual generator build used for the candidate. A
   release ZIP, executable, or minimal runnable build directory
   may be used only when those exact bytes will produce the report. Create a
   SHA-256 digest for that artifact, then place that exact allowlisted artifact in
   the candidate input root. A source-tree digest manifest, package label, commit
   name, or version string alone is not a runnable build. A name or version label
   alone is not sufficient.
   Do not archive a whole repository, `.git`, environment files, configuration
   files, credentials, or unrelated tree files merely to obtain a build label.
2. Copy `assets/attorney-generation-input.template.json` into the candidate's
   input root as canonical `generation-input.json`. Replace the fictional values,
   list every source, and make `generation_instructions` a complete report-writing
   instruction. `generator_artifacts` must identify the exact runnable build that
   will produce the report. All paths are relative to this input root. The capsule
   directory must be outside, not equal to or nested beneath, the input root.
3. Run `eval-gen-init`:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-gen-init \
     --input <candidate-input-root>/generation-input.json \
     --run <candidate-capsule-directory> \
     --nonce-hex <fresh-64-lowercase-hex>
   ```

4. Run `eval-gen-next` and save its JSON output outside the capsule:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-gen-next \
     --run <candidate-capsule-directory>
   ```

5. Read the expected generator-artifact hash from the current request and verify
   its digest immediately before launch. Fail closed on any mismatch. Launch that
   exact verified build to execute only the current generation packet, with that
   request as its sole matter evidence, in a fresh process or isolated host context.
   The build under evaluation must produce the report; a generic current host model
   or manually authored response is not a substitute for the captured build. Do not
   add another source, another report, prior conversation context, or a later
   evaluation artifact.
6. Copy `assets/attorney-generation-response.template.json` to the control
   directory. Write only the strict generation response envelope: copy
   `request_fingerprint`, use `operation: generate_report`, identify the actual
   provider, model, and isolation mode, and put the exact report in
   `payload.report_text`. Use `fresh_context` only when a fresh context was actually
   used; otherwise use `sequential_same_context`. Serialize canonical UTF-8 JSON
   with sorted keys, separators `,` and `:`, and no trailing newline. Keep the
   response file outside the capsule.
7. Run `eval-gen-submit`:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-gen-submit \
     --run <candidate-capsule-directory> \
     --response <control-directory>/generation-response.json
   ```

8. Run `eval-gen-verify` and require `"ok":true` before using the capsule:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-gen-verify \
     --run <candidate-capsule-directory>
   ```

Use `eval-gen-status --run <candidate-capsule-directory>` to inspect or resume an
existing capsule. `eval-gen-next` is an idempotent fetch of its one already-issued
request, not a new generation event. Never edit a capsule or submit a second response.

If the exact build cannot be resolved, digest-verified, or launched to produce the
report, do not call the result a build evaluation or build comparison. With the
user's authorization, the same machinery may instead run a **report evaluation
only**; identify the report's actual provenance and state expressly that no
captured build was shown to have produced it.

## Understand the capsule proof boundary

A completed capsule proves only this local sequence: the runner captured the exact
source, client-facts, instruction, and generator-artifact bytes; issued the
nonce-bound request; accepted the exact fingerprint-bound response; and sealed the
resulting report bytes in one replay-verifiable artifact graph. At `eval-init`, the
runner reopens each supplied capsule and binds its candidate identifier, exact report
bytes, question, source hashes, client-facts hash, generation record, and capsule root
to the evaluation case.
For a formal comparison, it also requires the exact captured generation-instruction
string to match across both verified capsules before any run directory is created.

That is an integrity and sequence record, not independent execution attestation.
Qualification `commit`, `archive_sha256`, and `language_treatments`, together with
response `provider_name`, `model_name`, and `judge_isolation`, are replay-sealed
attestations: replay proves that the recorded values have not changed. They are not
independent proof of the repository commit, archive origin, language handling,
host isolation, provider identity, model identity, or honest host behavior. Nor
does a capsule prove that the host or model used no other context or that the
provider and model labels are truthful. It does not prove that the host obeyed
the generation instructions or whether a machine owner recreated the capsule
after the fact. A malicious or compromised host can read information outside the
packet and still submit a syntactically valid response. Do not describe the capsule
as proof of chronology or execution truth.

## Prepare evaluation cases

After every new candidate capsule verifies, copy
`assets/attorney-evaluation-case.template.json` to the control directory and build
the schema `1.1` evaluation case. The template is a fictional current-law example,
not legal authority. Supply the common exact UTF-8 sources and optional client facts
at the case-relative paths, or replace those paths and all synthetic case metadata.
The loader preserves leading and trailing whitespace, final newlines, CRLF versus
LF, and a UTF-8 BOM; each retained hash therefore commits to the exact valid UTF-8
bytes. Set `client_facts_path` to `null` only when no client-facts text was provided.

For a newly generated report, set `generation_capsule_path` to its case-relative
capsule directory and `external_report_path` to `null`. The runner loads report bytes
only from that completed capsule. Its captured source bytes, client facts, question,
and candidate identifier must exactly match the common case.

For a historical or otherwise external report, use exactly one candidate in the
case and this alternative shape:

```json
{"candidate_id":"historical-report","external_report_path":"reports/historical-report.md","generation_capsule_path":null,"role":"candidate"}
```

When the user supplies several historical reports, create a separate one-candidate
case and run one absolute evaluation per report. You may summarize those absolute
results together, but issue no winner or tie, comparative score, ranking, or claim
of source parity. Formal comparison is unavailable for those historical report
bytes. To run one, generate new comparison reports through their own verified
capsules from the same exact question, source bytes, client-fact bytes, and
generation instructions. A two-report external or mixed case fails
before run creation with
`EVALUATION_SOURCE_PARITY_UNPROVEN`; never bypass that result by constructing
provenance fields yourself.

For current-law cases, independently supply operative primary text plus enough
official version, amendment, effective-date, repeal, and supersession evidence
to evaluate the declared as-of date. Do not use either candidate report as the
currentness record. For a locked suite, accept case paths from its public or
approved launcher/index and run each case independently; never inspect an
answer key, expected outcome, sealed mapping, or private report identity.

Choose a new evaluation run directory and generate a local random 64-character
lowercase hexadecimal seed. A changed case, source, report, capsule, rubric, or
response requires a new run. Never edit or add files within an initialized run.

### Ledger invariant contract

Every build, audit, and repair request carries the same versioned
ledger_invariant_contract. It is explanatory input; deterministic validation
remains authoritative. Repairs must globally recheck IDs, walk order,
relationships, citations, category fields, materiality, and audit binding.

The contract communicates the closed source-only ledger boundary to the evaluator;
it does not loosen, replace, or turn the deterministic validator into an
attestation. The runner deterministically enforces ledger identity and walk order,
relationship targets, exact source citations, category-required fields, concrete
materiality rationales, the remaining-audit request binding, and transaction-ready
remaining disputes. By contrast, an evaluator's statements that every initial
finding was resolved and that a complete recheck supports `complete: true` remain
evaluator attestations. The guarded submission and replay checks remain fail-closed:
an altered or unrecognized contract is refused rather than interpreted as a new
rule.

The contract is part of the build, audit, and repair request bytes, so its version
changes those requests' fingerprints. This effect is for new runs only. Start a
new run when using a newer contract; never insert, replace, or upgrade a contract
in an initialized or retained run. Replay uses the recorded recognized contract
generation and must not rewrite its request fingerprints.

For a refused response, use only the fixed safe diagnostic to make a bounded
mechanical repair in a new context. Discard the rejected response. Do not use,
quote, summarize, or feed detailed rejected-response content into a repair or any
later role.

## Run the blind role loop

Use this sequence without exposing its intermediate steps to the user.

1. **Initialize.** Run `eval-init` with `--case`, `--run`, and `--seed-hex`.
   Stop on input or integrity failure.
2. **Request the next role.** Run `eval-next --run <run-directory>`. Write `next-request.json`
   in the separate control directory. Read only `next-request.json` for the pending
   judgment.
3. **Execute one role.** Execute only the named role in `operation`. Treat
   `system_instructions` as the role instructions, `payload` as the entire
   evidence record, and `json_schema` as the exact required payload contract.
   When starting a fresh context, inject the host-neutral role-executor preamble
   below before supplying `next-request.json`.
4. **Respond.** Write only the Judge Response envelope to a control-directory
   response file.
5. **Preflight.** Treat preflight and commit as one guarded operation. The
   obsolete split sequence was to run `eval-preflight` before every
   `eval-submit`; do not invoke that sequence. `eval-submit-safe` applies the
   same semantic validation and writes nothing when it refuses a response.
   Never submit an invalid response. If a refusal is mechanical, discard the
   response and start a genuinely fresh isolated host context dedicated to that
   role repair. If the host cannot create that fresh context, stop the role;
   never repair in, or relabel, the initial or a prior repair context. Preflight
   again only by calling `eval-submit-safe`.

   Give the role one initial response and at most two mechanical repairs. A
   mechanical repair may correct only transport, canonical JSON, schema,
   request binding, or the pending operation contract; it may not change an
   evaluator's unfavorable substantive judgment. Track diagnostic codes for
   the current role and stop when the same diagnostic code occurs twice. Also
   stop after the second repair even if the diagnostic codes differ.
6. **Submit.** Never run `eval-submit` directly. Use `eval-submit-safe` for
   every initial or repaired evaluator response:

   ```bash
   python3 <skill-directory>/scripts/harvest_skill.py eval-submit-safe \
     --run <run-directory> \
     --response <control-directory>/response.json
   ```

   When it returns `"accepted":true`, it has validated and committed that exact
   response. When it returns `"accepted":false`, it has written no response or
   transition byte; handle only its fixed safe diagnostic as described below.
   Stop immediately on exit code `5`. Discard every rejected response and never
   let it enter the run. If the repair bound is exhausted, leave the pending run
   unchanged and report that no verified evaluation completed.
7. **Advance.** If the returned state is nonterminal, run `eval-next` again,
   replace the control copy of `next-request.json`, and repeat from step 2.
8. **Verify.** On `completed`, `case-invalid`, or `inconclusive`, run
   `eval-verify` with `--run <run-directory>`. A terminal nonzero disposition code is
   expected for some valid results; verification is complete only when its JSON
   says `"ok":true`.

To resume an existing run, run `eval-status --run <run-directory>`, then use
`eval-next` when the status is nonterminal. Resume from the runner's pending
operation; do not reconstruct progress by reading internal artifacts.

The runner advances the roles in this legal order:

1. Assess admission from the source-only record.
2. Build the source-only legal ledger.
3. Audit and, when requested, repair or referee it. **Seal the legal ledger**
   before any report grading.
4. **Grade Report A** twice against the sealed ledger.
5. Grade Report B twice when a comparator exists.
6. Referee only the material disputes supplied in the current packet.
7. Aggregate absolute and comparative outcomes deterministically.

Do not anticipate or manually select the next role. The current
`next-request.json` is authoritative.

### Isolation and blindness

Start a fresh isolated host context for every role when the host supports it,
and especially for each independent report grader. Inject the following
host-neutral role-executor preamble and pass the current `next-request.json` as
the only evidence. The transport instructions are not evidence: "only the
current `next-request.json`" means no other evidentiary context, not an absence
of instructions for constructing the response. The role must not read any other
file.

```text
Use next-request.json as the only evidence. system_instructions govern the
judgment; json_schema governs the inner payload. Return the exact outer Judge
Response envelope with schema_version 1.0, operation and request_fingerprint
copied from the request, the actual provider_name and model_name, a truthful
judge_isolation, and payload containing the schema-valid inner judgment:
{"judge_isolation":"<truthful isolation mode>","model_name":"<actual model>","operation":"<copy operation>","payload":<schema-valid inner judgment>,"provider_name":"<actual provider>","request_fingerprint":"<copy request_fingerprint>","schema_version":"1.0"}
A packet instruction to "Return only" the judgment excludes commentary; it does
not remove the outer envelope. Serialize the complete envelope as canonical
UTF-8 JSON with sorted object keys, separators `,` and `:`, and no trailing
newline. Do not read any other file.
```

Record `judge_isolation` as `fresh_context` only when that isolation was
actually used for that exact response. Start every mechanical repair in a new
isolated role context distinct from the initial response and every prior repair.
If that fresh context is unavailable, stop rather than repair in the same role
context. Never relabel an existing context or inherit the label from the
template or the discarded response.

Only for an initial role response, if the host cannot create a fresh context,
execute sequentially with the same context and record `judge_isolation` as
`sequential_same_context`. This fallback never applies to a mechanical repair;
if a genuinely fresh repair context is unavailable, that role stops. Never
claim fresh isolation when it did not occur. Even in the initial-response
sequential mode, use only the current packet: do not open or rely on the sealed
mapping, the other report, a prior grader response, or later-phase artifacts.
Do not read internal run artifacts to supplement a packet.

### Judge Response envelope

Use `assets/attorney-evaluation-response.template.json` only for the outer wire
shape. Its public `fresh_context` value is illustrative, not an observed default.
Explicitly replace `judge_isolation` with the truthful isolation of the exact
response being written. Copy `operation` and `request_fingerprint` exactly from
the current request. Identify the actual host and configured model. Put only the
object required by the request's `json_schema` in `payload`; when that schema
requires its own `request_fingerprint`, copy the same fingerprint there too.

For `admit_case`, include each of these exact material check codes once:
`AUTHORITY_ALIGNMENT`, `OPERATIVE_TEXT`, `CURRENTNESS_EVIDENCE`,
`LANGUAGE_RESOLUTION`, and `SOURCE_PARITY`. State whether each is satisfied and
ground the rationale and `source_ids` in the current source-only packet. Do not
rename the codes or substitute a custom admission checklist.

For `build_ledger`, copy `source_record.source_record_fingerprint` exactly into
the ledger's `case_fingerprint`; it is not the run's case-envelope fingerprint.
Before submission, preflight the complete draft against this closed invariant
checklist:

- use unique ledger and gap identifiers with no collisions, and list entries in
  unique, contiguous, zero-based `walk_order`;
- use only known, non-self relationships and known source IDs, including in gaps;
- use exact, nonduplicate half-open citations whose quoted text matches the source;
- give each operative category exact non-commentary source support;
- give every requirement, prohibition, or right both `actor` and `object`;
- give every deadline `timing`;
- give every exception entry a nonempty `conditions` or `exceptions` list;
  trigger or timing alone does not satisfy this;
- give every enforcement entry `enforcing_authority`, `enforcement_route`, and a
  `relationship_ids` link to a requirement or prohibition;
- give every penalty the same trigger relationship, and give every penalty or
  remedy a `consequence`; and
- give every materiality decision a concrete legal or practical rationale, not a
  generic importance label.

For `audit_ledger`, use only the current source record and return complete initial
audit findings. These may be qualitative findings rather than executable edits,
but each must use the packet's `audit_action_contract`, identify a permitted
action and materiality, and give a concrete, source-grounded rationale precise
enough for repair. For
`repair_ledger`, resolve every initial finding in the repaired ledger. Include in
`remaining_audit` only disputes that genuinely remain, and make every remaining
dispute transaction-ready under the same contract before sealing or refereeing.
Do not carry a qualitative-only finding into sealing.

For `grade_report`, copy the exact request fingerprint, anonymous label, and
sealed-ledger fingerprint. The inner grade uses `schema_version: "1.3"` even
though the outer Judge Response remains `"1.0"`. The packet includes the complete
common `source_record`, not only citations already selected for the ledger. Return
one entry grade for every sealed ledger entry and all eight narrative dimensions
exactly once. A `MISSING` entry has no `report_location` or `report_passage`; every
other content disposition has both a specific location and an exact report passage.
Each narrative score also binds an exact report passage. Do not use `NOT_APPLICABLE`.
A present out-of-ledger claim cannot be `MISSING` or `NOT_APPLICABLE`; its exact
claim passage must bind the common source-record fingerprint and either exact source
spans or an explicit closed-universe-absence basis. Use semantic finding codes only
in the contexts authorized by the schema and rubric.

Report-referee packets are fresh-context and dispute-scoped. They omit candidate and
anonymous labels, bind the opaque full-dispute fingerprint, and preserve each grader's
exact disputed passage in its alternative. Entry-grade and out-of-ledger-claim disputes
receive only those exact anonymous passages. For a narrative dispute, the packet expands
each grader passage to its complete enclosing Markdown H2 section and unions exact
sections without changing their bytes. Regulatory-walk, qualification-placement,
requirements-workplan-boundary, and scanability disputes receive the complete anonymous
report because those dimensions require report-wide context. If H2 resolution is absent,
boundary-spanning, or ambiguous, the packet fails safe to the complete anonymous report.
The referee also receives the relevant ledger or rubric context, common source record,
source spans, and explicit meanings of each allowed resolution.

Serialize the envelope as UTF-8 canonical JSON: sorted object keys, separators
`,` and `:`, and no trailing newline. Extra keys, Markdown fences, commentary,
or an unbound fingerprint are invalid. Never reuse a payload from another role.

## Handle terminal states and failures

Interpret runner exit codes together with the returned JSON:

| Code | Meaning | Required action |
|---|---|---|
| `0` | Pending, or verified completion with no failing report | Continue the loop or deliver after verification. |
| `2` | Input, path, envelope, or schema error | Correct the named input without loosening the schema; resubmit only if the run remains pending. |
| `3` | Terminal `CASE_INVALID` or `INCONCLUSIVE` | Run `eval-verify`, preserve the reasons, and report no winner. |
| `4` | Verified completed evaluation with at least one absolute `FAIL` | Treat it as a valid substantive result, run `eval-verify`, and report the failure. |
| `5` | Integrity or unsupported secure-storage failure | Stop. Do not deliver an evaluation as verified. |

Guarded refusals are controller-level mechanical defects and do not enter or
advance the run. Apply the bounded repair contract above; never submit a rejected
response merely to force a terminal state. An accepted `FAIL`, `CASE_INVALID`,
or other unfavorable substantive judgment is the evaluator's result, not a
repair trigger. `CASE_INVALID` means the authority record is not fit to score.
Neither terminal is a system crash, and neither permits manufacturing a
comparative winner. In a suite, continue independent cases after a substantive
`FAIL`, `CASE_INVALID`, or `INCONCLUSIVE`; stop the suite on integrity failure.

## Deliver the result

After successful verification, read the terminal `evaluation-result.json` and
`evaluation-report.md`. Return only:

- terminal disposition and case-readiness status;
- each report's absolute disposition and the comparative disposition, when
  available;
- concise material defects or the explicit invalid/inconclusive reason; and
- the path to the **Requirement-by-Requirement Matrix** in
  `evaluation-report.md`.

That matrix contains one row per sealed ledger entry and is the evidence-level
comparison the attorney needs. Do not substitute or point to the aggregate score table.
Do not narrate role packets, Python commands, fingerprints,
blinded labels, or internal retries unless the user asks for technical detail.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
