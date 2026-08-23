# Private Content Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the general report-authoring workflow at the earliest diagnosed
omission boundary, then require an exact reviewed build to generate a fresh
sealed anchor-case report that earns a verified Protocol 2.2 terminal `PASS`
without changing the evaluator, rubric, or locked evidence.

**Architecture:** Keep Protocol 2.2 evaluation semantics unchanged. First freeze
a public-safe provenance diagnosis of the completed beta.3 failure. Then harden
the packaged authoring instructions so an operative element cannot survive only
inside a source unit or citation quote while its unit, atom, claim, and visible
brief bindings say it is immaterial. Verify the public change, independently
review it, build an exact candidate, generate one new sealed report through the
normal skill workflow, and evaluate that report once with fresh isolated roles.
The private evaluation is the empirical content gate; this plan does not add a
new brittle semantic validator or require graders to agree word-for-word.

**Tech Stack:** Python 3.11-3.14, Pydantic v2, pytest, Ruff, mypy, stdlib
portable runner, deterministic ZIP packaging, Protocol 2.2 immutable evaluation
artifacts

**Spec:**
`docs/superpowers/specs/2026-08-23-private-content-readiness-design.md`

---

## Fixed boundaries

- The published beta.3 package, failed report, completed evaluation, locked
  question, source bytes, as-of date, client facts, case, rubric, thresholds,
  and evaluator semantics remain unchanged.
- The diagnosed earliest failure boundary is authoring materiality and atomic
  synthesis: responsive source units were admitted but closed as
  `not_material`, and some material content survived only inside exact citation
  quotes rather than claim text, rule atoms, visible brief bindings, or report
  prose.
- The initial implementation is an authoring-workflow correction, not a new
  lexical or keyword-based legal completeness gate. Do not add case-specific
  statutes, actors, requirement IDs, source IDs, quotations, expected sentences,
  or evaluator rationales to production code or public tests.
- Do not lower recall or coverage floors, alter requirement dispositions, retry
  substantive judgments, or require exact agreement between grader lanes.
- One diagnosis, one scoped implementation branch, at most two generation
  capsules, and one fresh private anchor evaluation are allowed. A second
  capsule is permitted only after a deterministic generation/content gate fails;
  a substantive evaluation result is never retried.
- Private source text, report text, legal strategy, and evaluator drafts stay
  under the governed private root. Public-safe records contain only categories,
  counts, hashes, fixed reason codes, and dispositions.
- The beta.2-to-beta.3 replay incompatibility is separate beta.4 work and is not
  part of this plan.
- PR creation, private evaluation initialization, merge, tag, and release each
  retain a separate owner checkpoint.

## Task 1: Freeze the beta.3 failure-provenance diagnosis

**Files:**

- Create privately: `<governed-root>/control/private-content-readiness-provenance.json`
- Create privately: `<governed-root>/control/private-content-readiness-public-safe.json`
- Read only: the sealed beta.3 generation capsule and Protocol 2.2 evaluation
  run
- Public Git changes: none

- [ ] **Step 1: Bind the existing immutable controls**

  From the owner-configured private root, record the existing generation-capsule
  root, report hash, evaluation manifest fingerprint, result fingerprint, and
  complete run-tree digest. Verify both the full and isolated-portable
  Protocol 2.2 verifiers before analysis.

  The private controller must accept the governed root through an already
  approved opaque configuration value. Do not search unrelated private paths,
  print source text, or write outside the owned `control/` directory.

- [ ] **Step 2: Build one provenance row per below-`met` requirement**

  Each private row must contain these structural fields:

  ```json
  {
    "requirement_fingerprint": "<sha256>",
    "grader_dispositions": ["partially_met"],
    "source_unit_ids": ["<bound-id>"],
    "lead_ids": ["<bound-id>"],
    "atom_ids": [],
    "claim_ids": ["<bound-id>"],
    "brief_locations": [],
    "rendered_locations": [],
    "first_failing_boundary": "unit-materiality-or-atomic-synthesis"
  }
  ```

  Private rows may retain exact internal IDs. The public-safe projection must
  replace them with counts and hashes and use only the approved boundary labels
  from the design spec.

- [ ] **Step 3: Assert the diagnosed pattern without exposing substance**

  The private matrix must prove all of the following:

  - the relevant source bytes and source units were admitted;
  - at least one responsive unit/lead path closed as `not_material` with no atom
    or gap;
  - at least one responsive proposition survived inside exact citation evidence
    but not in the source-supported claim text or atomic graph;
  - no responsive atom reached a visible brief binding or rendered location; and
  - no row is classified as evaluator interpretation when the final report lacks
    the supported proposition.

- [ ] **Step 4: Verify immutability and privacy**

  Recompute the beta.3 generation and evaluation hashes and require byte equality
  with Step 1. Scan the public-safe receipt for source text, report text, absolute
  private paths, client facts, evaluator prose, and internal legal identifiers.

  Expected public-safe outcome:

  ```text
  diagnosis_status=confirmed
  earliest_boundary=unit-materiality-or-atomic-synthesis
  evaluator_change_required=false
  private_artifact_mutation_count=0
  ```

- [ ] **Step 5: Review checkpoint**

  A fresh read-only reviewer checks the private matrix against the sealed
  artifacts. Stop if any below-`met` requirement lacks a row or if a proposition
  is actually visible in the report. Do not start code changes until the reviewer
  agrees that the failure is generator loss rather than evaluator preference.

## Task 2: Add RED tests for the general authoring invariant

**Files:**

- Modify: `tests/skill/test_skill_package.py`
- Modify: `tests/combine/test_stages.py`
- Test: `tests/skill/test_skill_package.py`
- Test: `tests/combine/test_stages.py`

- [ ] **Step 1: Add one cross-surface materiality-challenge test**

  Add this test near
  `test_skill_requires_an_atomic_rule_graph_before_prose_drafting` in
  `tests/skill/test_skill_package.py`:

  ```python
  def test_skill_requires_quote_to_atom_materiality_challenge() -> None:
      paths = (
          "SKILL.md",
          "references/research-protocol.md",
          "references/draft-schema.md",
          "src/regulatory_harvest/analysis/prompts/build-v1.md",
      )
      documents = {
          path: (ROOT / path).read_text(encoding="utf-8") for path in paths
      }
      for path, document in documents.items():
          folded = document.casefold()
          assert "materiality challenge" in folded, path
          assert "a citation quote is not coverage" in folded, path
          assert "survives only in the quotation" in folded, path
          assert "independently operative" in folded, path
          assert "map it to an atom or preserve a source-bound gap" in folded, path

      combined = "\n".join(documents.values()).casefold()
      for forbidden in (
          "regional compliance steward",
          "third-party assurance reviewer",
          "rapid corrective direction",
          "jurisdiction-local officer",
      ):
          assert forbidden not in combined
  ```

  These deliberately synthetic terms are regression guards against copying a
  test scenario's answer into product instructions. If any term already exists
  for an unrelated public example, replace only that assertion with a
  structurally equivalent synthetic token that is absent at the task base; do
  not delete the no-overfitting guard.

- [ ] **Step 2: Add the actual model-request assertion**

  Extend `test_model_requests_use_the_versioned_attorney_briefing_prompts` in
  `tests/combine/test_stages.py`:

  ```python
  for term in (
      "materiality challenge",
      "a citation quote is not coverage",
      "survives only in the quotation",
      "map it to an atom or preserve a source-bound gap",
  ):
      assert term in build_request.system_instructions.casefold()
  ```

  This proves the changed packaged prompt is the prompt actually supplied to
  the build model, not dead documentation.

- [ ] **Step 3: Run RED tests**

  Run:

  ```bash
  PYTHONPATH=src uv run pytest \
    tests/skill/test_skill_package.py::test_skill_requires_quote_to_atom_materiality_challenge \
    tests/combine/test_stages.py::test_model_requests_use_the_versioned_attorney_briefing_prompts \
    -q
  ```

  Expected: both tests fail because the general materiality/quote-to-atom
  instructions are absent. Record the exact failures in the implementation
  report before changing instruction files.

- [ ] **Step 4: Commit the RED tests**

  ```bash
  git add tests/skill/test_skill_package.py tests/combine/test_stages.py
  git commit -m "test: expose report materiality omissions"
  ```

## Task 3: Harden the packaged authoring workflow

**Files:**

- Modify: `SKILL.md`
- Modify: `references/research-protocol.md`
- Modify: `references/draft-schema.md`
- Modify: `src/regulatory_harvest/analysis/prompts/build-v1.md`
- Test: `tests/skill/test_skill_package.py`
- Test: `tests/combine/test_stages.py`

- [ ] **Step 1: Add the same bounded invariant to all four instruction surfaces**

  Add a short **Materiality challenge** immediately after atomic graph creation
  and before prose synthesis. Preserve each document's existing style, but keep
  these requirements semantically identical:

  ```text
  A citation quote is not coverage. Before assigning not_material or drafting
  prose, compare each responsive source unit, provision lead, and exact citation
  quote against the claim and atomic graph. If an actor, duty, right,
  qualification, independence condition, location condition, threshold,
  deadline, enforcement authority, route, remedy, or consequence survives only
  in the quotation, map it to an atom or preserve a source-bound gap. A nearby
  claim or atom about the same topic is not a substitute for the independently
  operative element.
  ```

  Also require a concrete `not_material` rationale to identify one of these
  ordinary reasons in prose:

  - navigation or publication metadata;
  - exact duplication of a named mapped atom;
  - outside the scoped question;
  - nonoperative or superseded text; or
  - evidentiary context that states no independent legal proposition.

  This is an authoring instruction, not a parsed enum. Do not change the draft
  schema, coverage contract version, validator, portable runtime, or historical
  replay behavior in this task.

- [ ] **Step 2: Make the final omission pass compare graph to report**

  Strengthen the existing adversarial omission review so it explicitly checks:

  1. responsive unit/lead to atom or gap;
  2. citation quote to narrowly stated source-supported claim;
  3. claim to stated atom elements and relationships;
  4. every critical/material atom to one visible legal-analysis binding; and
  5. visible binding to rendered report prose without losing material actors,
     conditions, authorities, or consequences during compression.

  The instruction must say that deterministic `completed` status proves schema,
  evidence, and binding consistency but does not excuse a substantively false
  `not_material` decision.

- [ ] **Step 3: Keep the correction general and finishable**

  Confirm the edited files do **not**:

  - name the private law, jurisdiction, report, source IDs, requirement IDs,
    evaluator findings, or expected report wording;
  - require every unit to become an atom;
  - prohibit legitimate `not_material` dispositions;
  - require every grader to agree;
  - introduce a keyword list or lexical legal-completeness classifier; or
  - add another automatic retry loop.

  The intended behavior is a better substantive authoring pass, not a stricter
  machine gate that makes ordinary source packets impossible to finish.

- [ ] **Step 4: Run focused GREEN tests**

  ```bash
  PYTHONPATH=src uv run pytest \
    tests/skill/test_skill_package.py::test_skill_requires_quote_to_atom_materiality_challenge \
    tests/skill/test_skill_package.py::test_skill_requires_expansive_analysis_before_evidence_hardening \
    tests/skill/test_skill_package.py::test_skill_requires_an_atomic_rule_graph_before_prose_drafting \
    tests/combine/test_stages.py::test_model_requests_use_the_versioned_attorney_briefing_prompts \
    -q
  ```

  Expected: 4 passed.

- [ ] **Step 5: Run package-instruction coherence tests**

  ```bash
  PYTHONPATH=src uv run pytest \
    tests/skill/test_skill_package.py \
    tests/combine/test_stages.py \
    tests/test_packaging_metadata.py \
    -q
  ```

  Expected: all selected tests pass with only repository-known warnings.

- [ ] **Step 6: Commit the authoring correction**

  ```bash
  git add \
    SKILL.md \
    references/research-protocol.md \
    references/draft-schema.md \
    src/regulatory_harvest/analysis/prompts/build-v1.md
  git commit -m "fix: challenge material omissions before report synthesis"
  ```

## Task 4: Verify the public candidate without private evidence

**Files:**

- Modify only if a test exposes an actual regression: files already authorized
  in Tasks 2-3
- Create ignored execution report:
  `.superpowers/sdd/2026-08-23-private-content-readiness/public-candidate-report.md`
- Test: retained analysis, package, CLI, evaluation, and release suites

- [ ] **Step 1: Run focused analysis and report gates**

  ```bash
  PYTHONPATH=src uv run pytest \
    tests/analysis/test_drafts.py \
    tests/analysis/test_atomic_coverage.py \
    tests/analysis/test_proposition_coverage.py \
    tests/analysis/test_coverage_common.py \
    tests/analysis/test_report.py \
    tests/analysis/test_report_parity.py \
    tests/scripts/test_harvest_skill.py \
    tests/scripts/test_harvest_portable.py \
    -q
  ```

- [ ] **Step 2: Run package and end-to-end gates**

  ```bash
  PYTHONPATH=src uv run pytest \
    tests/scripts/test_build_skill.py \
    tests/skill/test_skill_package.py \
    tests/e2e/test_skill_flow.py \
    tests/test_packaging_metadata.py \
    -q
  ```

- [ ] **Step 3: Run static verification**

  ```bash
  uv run ruff check .
  uv run mypy src
  git diff --check origin/main...HEAD
  ```

  Expected: all commands exit 0. Existing direct-script mypy baselines may be
  measured separately, but no new diagnostic is allowed.

- [ ] **Step 4: Run the full repository suite**

  ```bash
  uv run pytest -q
  ```

  Capture the exact pass/skip/warning count and runtime from the terminal output.
  Do not infer success from progress output.

- [ ] **Step 5: Build twice and audit exact archives**

  Use two clean detached exports of the exact candidate commit. Run the retained
  no-local package builder for each, require byte-identical ZIPs, and record:

  - commit SHA;
  - archive SHA-256 and byte length;
  - sorted unique member count;
  - member-to-Git-blob equality;
  - release-audit result;
  - full and isolated-portable `prepare`, `finalize`, and evaluation help checks;
    and
  - confirmation that the archive contains the four changed instruction files.

- [ ] **Step 6: Exercise Python 3.11-3.14 CI**

  Push nothing yet. First confirm the touched surfaces are interpreter-neutral
  Markdown and tests. After the owner authorizes a draft PR, require the normal
  Linux Python 3.11, 3.12, 3.13, and 3.14 matrix to pass on the exact PR head.

- [ ] **Step 7: Sequential self-review**

  Inspect `origin/main...HEAD` for:

  - anchor-specific wording;
  - accidental evaluator, rubric, threshold, protocol-default, or runtime edits;
  - instruction drift across the four surfaces;
  - rules that make all `not_material` uses invalid;
  - untracked private data; and
  - package-manifest drift.

  Resolve every Critical or Important finding before requesting independent
  review.

## Task 5: Obtain independent review and prepare a draft PR

**Files:**

- Create ignored review package:
  `.superpowers/sdd/2026-08-23-private-content-readiness/review-<base>..<head>.diff`
- Update ignored report:
  `.superpowers/sdd/2026-08-23-private-content-readiness/public-candidate-report.md`
- Public Git changes: none unless review finds a defect

- [ ] **Step 1: Build an exact review package**

  ```bash
  git diff --full-index --binary origin/main...HEAD > \
    .superpowers/sdd/2026-08-23-private-content-readiness/review-main..candidate.diff
  shasum -a 256 \
    .superpowers/sdd/2026-08-23-private-content-readiness/review-main..candidate.diff
  ```

  Record the exact base, head, file list, line count, byte count, and SHA-256.

- [ ] **Step 2: Request fresh independent review**

  The reviewer receives the approved design, this plan, the exact diff package,
  focused/full/static/build evidence, and the generalized public-safe provenance
  receipt. The reviewer must not receive private source or report text.

  Review questions:

  - Does the change address the diagnosed authoring boundary?
  - Is the instruction coherent across all packaged surfaces?
  - Is any language case-specific or likely to force false atoms/gaps?
  - Are evaluator and deterministic validator semantics unchanged?
  - Is the change testable, packaged, and usable in the actual build prompt?

  Required verdict: zero open Critical or Important findings.

- [ ] **Step 3: Stop for owner approval before external mutation**

  Present the exact reviewed commit, archive hash, review verdict, CI status, and
  proposed draft-PR title/body. Do not push or open the PR until the owner gives
  explicit authorization.

- [ ] **Step 4: After authorization, push and open a draft PR**

  Use a `codex/` branch. The PR title should describe content-completeness
  authoring, not claim private readiness. Mark the PR draft and state that merge
  is blocked on the private anchor result.

  Do not include private paths, source text, report text, evaluator prose, or
  internal identifiers in the PR.

## Task 6: Generate a fresh anchor report from the exact reviewed PR tree

**Files:**

- Create privately: one new generation input, controller namespace, generation
  capsule, analysis draft, bundle, report, audit, coverage review, and validation
  receipt under the governed root
- Read only: unchanged qualification, locked source bytes, question, as-of date,
  client facts, and failed beta.3 control artifacts
- Public Git changes: none

- [ ] **Step 1: Bind the exact candidate**

  Verify the reviewed PR head, deterministic ZIP hash, ZIP member bytes, package
  inventory, prompt bytes, and installed bytes. Reverify the unchanged
  qualification and all locked input hashes. Record only public-safe hashes and
  counts outside the governed root.

- [ ] **Step 2: Author in a fresh isolated generation context**

  Give one fresh context only:

  - the exact installed skill instructions;
  - the sealed generation request; and
  - no beta.3 report, evaluator response, grader rationale, or desired sentence.

  The sealed generation request is the sole matter-evidence input. The role must
  derive any dossier and normalized sources inside the packet-only public
  workflow from that request; the controller must not inject them as separate
  context.

  The role produces a complete `analysis-draft.json` through the normal public
  schema. It must not receive the provenance matrix's private substantive
  details; the product instructions, not evaluator coaching, must drive the
  correction.

- [ ] **Step 3: Run one fresh isolated omission review before finalization**

  A separate fresh context receives the candidate draft, packaged
  materiality-challenge instructions, and the verified dossier produced inside
  the same packet-only public workflow from the sealed generation request. The
  dossier and normalized text must be request- and capsule-bound outputs of that
  workflow, not separately injected matter evidence. The role returns a private
  structured challenge limited to target IDs, boundary categories, and whether
  each cited operative element reaches atom/claim/visible binding. It does not
  grade the report or receive the prior evaluator result.

  If the challenge identifies a real omission, one fresh repair context may
  revise the draft once. Preserve the pre-repair draft and content-free receipt;
  do not manually edit report prose.

- [ ] **Step 4: Finalize and seal one fresh generation capsule**

  Run full and isolated-portable finalization from the exact candidate package.
  Require byte parity and:

  ```text
  status=completed
  valid=true
  proposition_coverage_valid=true
  provision_recall_valid=true
  evidence_precision_valid=true
  coverage_issue_count=0
  ```

  Seal the generated report as the sole candidate report in a new generation
  capsule. The report must not be hand-edited after finalization.

- [ ] **Step 5: Apply the private pre-evaluation content gate**

  Re-run the structural provenance trace against the fresh artifacts. Every
  previously diagnosed generalized omission row must now reach source unit,
  atom, source-supported claim, visible brief binding, and rendered location—or
  a genuine source-bound gap when the source cannot establish it.

  This gate checks the known mechanism only; it is not a hidden second rubric.
  A failure permits one return to Task 3 and one replacement capsule. A second
  failure stops the cycle before evaluation.

- [ ] **Step 6: Stop for explicit private-run authorization**

  Report the exact PR head, package and capsule hashes, deterministic validation
  results, omission-review result, privacy scan, and confirmation that the
  beta.3 controls are unchanged. Do not initialize the Protocol 2.2 run until
  the owner explicitly authorizes it.

## Task 7: Run one fresh private Protocol 2.2 anchor evaluation

**Files:**

- Create privately: exactly one new Protocol 2.2 run and content-free controller
  receipts
- Read only: the sealed fresh generation capsule and unchanged case/rubric
- Public Git changes: none

- [ ] **Step 1: Initialize once and verify the pending state**

  Initialize exactly one new run with the sealed fresh report. Verify full and
  isolated-portable parity before dispatching a role. Record manifest, inventory,
  request, compiler-contract, package, capsule, case, and rubric fingerprints.

- [ ] **Step 2: Use a fresh isolated context for every evaluator role**

  For source review, source audit, each source referee, every ordinary/contested
  grader call, and final comparison when applicable:

  - spawn a fresh isolated evaluator context;
  - provide only the exact current request and fixed content-free handoff rules;
  - allow one initial draft and at most one fresh mechanical clarification;
  - never show a rejected draft to a later context;
  - accept every valid substantive response once; and
  - never retry an unfavorable judgment.

- [ ] **Step 3: Verify every guarded transition**

  Before and after each submission, require exact request fingerprint, attempt,
  operation, run-root identity, and tree binding. A rejected response must be
  write-free. A provider/controller failure pauses the same run; it never becomes
  a substantive `INCONCLUSIVE` result.

- [ ] **Step 4: Preserve the terminal result without interpretation-driven retry**

  At terminal state, verify:

  - full/portable status and verification parity;
  - exact manifest, result, aggregate, and sensitivity fingerprints;
  - expected role/call counts;
  - zero rejected-draft persistence;
  - zero bytecode or private leakage; and
  - no integrity or unsupported-storage issue.

  The anchor gate passes only for terminal `PASS`. A terminal `FAIL` or
  substantive `INCONCLUSIVE` is valid evidence but does not pass readiness.

- [ ] **Step 5: Enforce the bounded stop policy**

  If the result is not `PASS`, preserve it, perform read-only provenance, classify
  recurrence/new defect/legitimate uncertainty, and stop. Do not begin another
  implementation or private-run cycle under this authorization.

- [ ] **Step 6: Write the public-safe readiness receipt**

  Emit exactly one of:

  ```text
  PRIVATE CONTENT READINESS PASSED: ANCHOR REPORT VERIFIED PASS
  ```

  or

  ```text
  PRIVATE CONTENT READINESS NOT PASSED: SUBSTANTIVE RESULT PRESERVED
  ```

  Include only reviewed commit, package/capsule/run hashes, counts, fixed reason
  codes, terminal disposition, parity result, and privacy status.

## Task 8: Integrate only the exact privately evaluated tree

**Files:**

- Public Git changes: none unless merge conflict resolution would change the
  reviewed tree
- Release artifacts: deferred to a separately approved beta.4 task

- [ ] **Step 1: Stop for merge authorization**

  Present the private readiness receipt, exact draft-PR head, CI state, and
  independent-review verdict. Do not merge automatically.

- [ ] **Step 2: Prove tree identity before merge**

  Immediately before merge, require the PR head tree to equal the privately
  evaluated tree. If `main` moved, update through a clean merge/rebase, rerun the
  affected public gates, rebuild the archive, and rebind before deciding whether
  private evidence still applies. Never silently resolve a conflict into an
  unevaluated tree.

- [ ] **Step 3: Merge only after explicit approval**

  Merge the exact approved tree. Verify `main` contains the same changed blobs
  and no private artifacts. Do not tag or publish beta.4 in this task.

- [ ] **Step 4: Optional confidence evidence**

  After anchor `PASS`, and only with separate authorization, run at most two
  diverse private smoke cases from the design spec. Their job is to detect
  recurrence of the diagnosed omission mechanism, not to demand universal
  grader agreement or universal terminal `PASS`.

## Final completion checklist

- [ ] Beta.3 failed report, generation capsule, and completed run are unchanged.
- [ ] Every below-`met` requirement has a reviewed provenance row.
- [ ] The only public behavior change is the general authoring/materiality
  challenge justified by that provenance.
- [ ] No private or anchor-specific substance appears in Git, CI, PR, or archive.
- [ ] Evaluator, rubric, thresholds, protocol default, and strict artifact checks
  are unchanged.
- [ ] Focused, retained, full, static, package, deterministic-build, audit, and
  Python-version gates pass on the exact candidate.
- [ ] Independent review has zero open Critical or Important findings.
- [ ] A fresh reviewed build—not a human edit—produces the evaluated report.
- [ ] The fresh generation capsule passes deterministic and known-mechanism
  content gates.
- [ ] Exactly one fresh private run uses fresh isolated evaluator roles and
  reaches verified terminal `PASS`.
- [ ] The evaluated PR tree and merged tree are identical.
- [ ] Later beta.4 tagging/publication and replay-compatibility work remain
  separately authorized.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
