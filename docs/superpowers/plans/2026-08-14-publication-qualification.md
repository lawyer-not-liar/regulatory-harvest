# Publication Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the verified evaluator-reliability and proposition-coverage-v2 implementations into one reproducible release candidate, then make a bounded publication-readiness decision from one designated gate and at most one complete qualified three-case suite.

**Architecture:** Treat qualification as a fail-closed controller run, not an open-ended improvement loop. Build and install one immutable archive, qualify and freeze source-only case records, run one designated substantive gate, and run the complete suite once only if that gate passes. Store private case material outside Git; commit only generic release documentation after all substantive and technical gates pass.

**Tech Stack:** Git, Python 3.11+, existing reproducible skill builder and release auditor, Regulatory Harvest generation/evaluation capsules, canonical JSON/SHA-256 receipts, pytest, Ruff, mypy, standard-library portable runner.

## Global Constraints

- Execute this plan only after both `2026-08-14-evaluator-reliability.md` and `2026-08-14-proposition-coverage-v2.md` are implemented, reviewed, and committed.
- Use one immutable commit and one verified archive for every generation and evaluation in the qualification cycle.
- Qualify source records without reading either candidate report or comparator report.
- Freeze admitted case bytes for the complete cycle; any source change creates a new case version and requires a new explicit cycle authorization.
- Run one designated substantive case first. Anything other than an absolute Regulatory Harvest `PASS` stops the cycle.
- Run the complete three-case suite exactly once only after the designated gate passes.
- Do not retry unfavorable substantive results. Mechanical response repair is limited to one initial response plus at most two fresh-context repairs and stops when the same diagnostic code occurs twice.
- Integrity failure stops the case and suite immediately. A controller or tool failure must be reproduced with synthetic data before any implementation repair.
- Private sources, reports, ledgers, mappings, responses, grades, scores, local paths, and answer text remain outside Git.
- Do not publish, push, open a pull request, create a release, change repository visibility, or install to another person's environment. Publication requires separate final user authorization.

---

## Artifact boundaries

Tracked public artifacts:

- `docs/release-checklist.md`: generic publication gates and attorney-review limitation.
- `docs/evaluation.md`: generic qualified-suite method and metric definitions.
- `README.md`: installation, normal attorney workflow, limitations, and local-storage boundary.
- `CHANGELOG.md`: public-safe release-candidate summary only after all gates pass.
- `dist/regulatory-harvest-skill.zip`: reproducible release archive; keep untracked until final publication authorization unless repository policy explicitly tracks release archives.

Private ignored artifacts:

- `qualification-policy.json`: immutable commit, designated case, attempt limits, and thresholds before the archive exists;
- `qualification-controller.json`: immutable commit, archive, install, case, and attempt limits;
- one qualification capsule per case version;
- one generation capsule per fresh candidate;
- one evaluation capsule per admitted case;
- one terminal suite receipt containing only approved high-level results and artifact roots;
- one bounded defect report when the cycle stops.

The private controller must use physical absolute paths internally, but no such path may be copied into a tracked file or commit message.

### Task 1: Freeze the implementation and record the controller contract

**Files:**
- Read: both preceding implementation plans and their task reports.
- Read: `docs/superpowers/specs/2026-08-14-publication-readiness-v2-design.md`
- Private create: `qualification-policy.json`
- No tracked file changes.

**Interfaces:**
- Consumes: reviewed evaluator-reliability and proposition-coverage-v2 commit ranges.
- Produces: one canonical policy record with immutable commit, attempt limits, and publication thresholds; Task 2 binds the archive into the final controller.

- [ ] **Step 1: Verify the worktree boundary**

Run from the repository root:

```bash
git status --short
git rev-parse HEAD
git diff --check
git diff --cached --check
```

Record the exact pre-existing unrelated changes. Refuse to proceed if implementation changes are unstaged, staged, or uncommitted.

- [ ] **Step 2: Run the public implementation gate**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
```

Expected: the full test suite passes with only explicitly documented skips; Ruff and mypy exit `0`.

- [ ] **Step 3: Write and validate the private policy record**

Validate the private canonical JSON through this exact schema:

```python
class PublicationThresholds(StrictModel):
    claim_precision_minimum: float = Field(default=0.95, ge=0.95, le=0.95)
    critical_recall_minimum: float = Field(default=1.0, ge=1.0, le=1.0)
    required_absolute_passes: Literal[3] = 3
    weighted_recall_minimum: float = Field(default=0.9, ge=0.9, le=0.9)


class QualificationPolicy(StrictModel):
    schema_version: Literal["publication-qualification-policy-v1"]
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    designated_case_id: str = Field(min_length=1)
    full_suite_case_count: Literal[3] = 3
    mechanical_attempt_limit: Literal[3] = 3
    same_diagnostic_repeat_limit: Literal[2] = 2
    publication_thresholds: PublicationThresholds
```

Populate `commit` from the frozen `git rev-parse HEAD` and `designated_case_id` from the approved private case manifest. Assert sorted keys, compact UTF-8 JSON, no trailing newline, and exactly three suite cases. This file remains in the approved private workspace.

- [ ] **Step 4: Record the no-spiral stop rules**

The controller must refuse:

```text
generation before every case is source-qualified
full-suite execution before the designated case passes
any fourth mechanical response attempt
continuing after the same safe diagnostic code appears twice
substantive retry after an unfavorable judgment
another design iteration or candidate run without new user authorization
```

- [ ] **Step 5: Recheck repository state**

```bash
git status --short
git diff --check
git diff --cached --check
```

Expected: no new tracked or untracked private artifact exists in the repository.

### Task 2: Build, audit, and install one immutable archive

**Files:**
- Read: `scripts/build_skill.py`
- Read: `scripts/audit_release.py`
- Read: `scripts/skill-package-files.txt`
- Private create: two temporary build directories and one recoverable install backup.
- No tracked file changes.

**Interfaces:**
- Consumes: the frozen clean commit from Task 1.
- Produces: one byte-reproducible ZIP, clean release audit receipt, and byte-matching local installation.

- [ ] **Step 1: Build twice from separate clean Git archives**

Create two directories with `mktemp -d`. Clone the local repository with full history into each, detach both at the frozen commit, and run in each clone:

```bash
RH_SOURCE_REPO="$(git rev-parse --show-toplevel)"
RH_COMMIT="$(git rev-parse HEAD)"
RH_BUILD_ONE="$(mktemp -d)"
RH_BUILD_TWO="$(mktemp -d)"
git clone --quiet --no-local "$RH_SOURCE_REPO" "$RH_BUILD_ONE/repo"
git clone --quiet --no-local "$RH_SOURCE_REPO" "$RH_BUILD_TWO/repo"
git -C "$RH_BUILD_ONE/repo" checkout --quiet --detach "$RH_COMMIT"
git -C "$RH_BUILD_TWO/repo" checkout --quiet --detach "$RH_COMMIT"
(cd "$RH_BUILD_ONE/repo" && python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip)
(cd "$RH_BUILD_TWO/repo" && python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip)
```

Do not build from the dirty working tree.

- [ ] **Step 2: Prove byte reproducibility**

```bash
cmp --silent "$RH_BUILD_ONE/repo/dist/regulatory-harvest-skill.zip" "$RH_BUILD_TWO/repo/dist/regulatory-harvest-skill.zip"
shasum -a 256 "$RH_BUILD_ONE/repo/dist/regulatory-harvest-skill.zip" "$RH_BUILD_TWO/repo/dist/regulatory-harvest-skill.zip"
unzip -t "$RH_BUILD_ONE/repo/dist/regulatory-harvest-skill.zip"
```

Expected: `cmp` exits `0`, both SHA-256 values match, and every ZIP member passes integrity testing.

- [ ] **Step 3: Audit the repository snapshot and archive**

```bash
(cd "$RH_BUILD_ONE/repo" && python3 scripts/audit_release.py --repo . --archive dist/regulatory-harvest-skill.zip --json)
```

Run this command inside the clean snapshot. Require `ok: true` and zero automated privacy findings. Review the complete archive member list against `scripts/skill-package-files.txt`.

- [ ] **Step 4: Install recoverably**

Resolve the active Regulatory Harvest skill directory from the local agent configuration. Confirm it is a physical directory, not a symlink. Move only that exact directory to a timestamped sibling backup, create the original directory anew, and extract the verified archive there. Never recursively remove the parent directory.

- [ ] **Step 5: Verify the installed bytes and smoke surfaces**

Compare every installed file hash to the archive member bytes, then run the installed full and portable help commands. Require both exit `0`, and require the installed copies of the v2 reconciler, qualification module, `SKILL.md`, and package metadata to exist.

- [ ] **Step 6: Bind the archive to the private controller**

Create `qualification-controller.json` by copying every validated policy field, changing `schema_version` to `publication-qualification-v1`, and adding `archive_sha256` with pattern `^[0-9a-f]{64}$`. Revalidate the copied fields and archive digest, canonicalize the result, and verify it again. Do not rebuild after this point in the qualification cycle.

### Task 3: Qualify and freeze all three source-only cases

**Files:**
- Private read: approved source packets and case definitions only.
- Private create: one qualification capsule per case version.
- No tracked file changes.

**Interfaces:**
- Consumes: immutable archive, candidate-free case records, and the evaluator qualification commands from the evaluator-reliability plan.
- Produces: three replay-valid `ADMITTED` qualification receipts and frozen source-record roots.

- [ ] **Step 1: Establish each declared as-of record**

For every case, require:

```text
authority alignment
operative primary text
official currentness evidence for the declared as-of date
language resolution or bounded translation treatment
source-parity contract: one frozen source record designated for both candidate and comparator
```

Currentness research must use official public primary authority selected without access to either report. Any missing material causes a new case version; never overwrite the old case.

- [ ] **Step 2: Initialize source-only qualification capsules**

Use the installed `eval-qualify-init` command with one physical empty capsule directory and one canonical case input per version. Store the immutable commit and archive digest in the capsule metadata.

- [ ] **Step 3: Obtain one independent qualification judgment per case**

Provide the role only the source-only admission request. It must not receive the candidate, comparator, mapping, prior response, score, or expected conclusion.

- [ ] **Step 4: Submit and verify qualification**

Use `eval-qualify-submit`, then `eval-qualify-status` and `eval-qualify-verify`. A safe mechanical refusal gets a fresh context with only the request and diagnostic, subject to the same three-attempt and repeated-code stops; an admitted or case-invalid substantive judgment is final. Require a terminal `ADMITTED` receipt, valid replay, matching source-record fingerprint, matching immutable commit, and matching archive digest.

- [ ] **Step 5: Fail closed on an unready case**

If any case is not admitted, stop before generation. Write one private bounded defect report validated by this public-safe schema:

```python
class QualificationDefectCode(StrEnum):
    AUTHORITY_ALIGNMENT_FAILED = "AUTHORITY_ALIGNMENT_FAILED"
    OPERATIVE_TEXT_NOT_ESTABLISHED = "OPERATIVE_TEXT_NOT_ESTABLISHED"
    CURRENTNESS_NOT_ESTABLISHED = "CURRENTNESS_NOT_ESTABLISHED"
    LANGUAGE_UNRESOLVED = "LANGUAGE_UNRESOLVED"
    SOURCE_PARITY_NOT_ESTABLISHED = "SOURCE_PARITY_NOT_ESTABLISHED"


class PublicationDefect(StrictModel):
    schema_version: Literal["publication-defect-v1"]
    cycle_status: Literal["STOPPED_CASE_NOT_READY"]
    defect_classes: list[QualificationDefectCode] = Field(min_length=1)
    next_authorized_action: Literal["repair and version the source record"]
    publication_ready: Literal[False]
```

Do not repair, regenerate, or start another cycle automatically.

- [ ] **Step 6: Freeze admitted bytes**

Record all three qualification artifact roots in the private controller. Hash every source record again immediately before generation and refuse any mismatch.

### Task 4: Run the designated substantive gate once

**Files:**
- Private create: one fresh generation capsule and one fresh evaluation capsule.
- Private create on failure: one bounded defect report.
- No tracked file changes.

**Interfaces:**
- Consumes: the designated admitted case, immutable installed archive, and frozen comparator.
- Produces: one verified terminal result or a fail-closed stop receipt.

- [ ] **Step 1: Generate from a fresh isolated context**

Bind the generation capsule to the immutable commit, archive digest, and designated qualification root. Allow the ordinary finite draft-finalization repair loop, but accept a report only when finalization is `completed` and all three generation booleans are true:

```text
evidence_precision_valid
proposition_coverage_valid
provision_recall_valid
```

- [ ] **Step 2: Verify generation before evaluation**

Verify canonical response bytes, report payload equality, capsule root, replay, source-record fingerprint, commit, and archive digest. Any integrity mismatch stops the cycle.

- [ ] **Step 3: Initialize the evaluator from the frozen case**

Use the admitted source-record root and unchanged comparator. Confirm the anonymous mappings are sealed before dispatching any evaluator role.

- [ ] **Step 4: Use guarded submission for every response**

For each pending role, use `eval-submit-safe`. On a safe mechanical refusal, create a fresh role with only the same pending request plus the bounded diagnostic. Stop the role after three total attempts or when the same diagnostic code occurs twice. Never submit a response whose preflight result is false, and never retry an accepted unfavorable judgment.

- [ ] **Step 5: Verify the terminal evaluation**

Require terminal capsule and history verification, matching commit/archive/case roots, zero integrity findings, and a deterministic receipt.

- [ ] **Step 6: Apply the designated stop gate**

Proceed only if Regulatory Harvest receives an absolute `PASS` and satisfies:

```text
critical recall = 1.0
weighted recall >= 0.90
claim precision >= 0.95
narrative safety gates pass
deterministic safety gates pass
```

Any other result ends the cycle. Write one private defect report with only aggregate metrics and stable high-level defect codes, then stop without another candidate or design iteration.

### Task 5: Run the complete qualified suite once

**Files:**
- Private create: three fresh generation capsules and three fresh evaluation capsules.
- Private create: one canonical terminal suite receipt.
- No tracked file changes.

**Interfaces:**
- Consumes: designated absolute PASS, all three frozen qualifications, immutable installed archive, unchanged comparators.
- Produces: one complete three-case terminal record and one publication-readiness boolean.

- [ ] **Step 1: Reverify all frozen inputs**

Before the first full-suite generation, recompute and compare every qualification root, source-record fingerprint, comparator fingerprint, commit, archive digest, and installed-file hash. A mismatch stops the suite before any new candidate is generated.

- [ ] **Step 2: Run exactly one fresh candidate per case**

For each case, repeat Task 4's generation and guarded evaluation protocol in a fresh isolated context. Substantive outcomes may finish independently once the suite has begun; integrity failure stops all remaining work.

- [ ] **Step 3: Verify every terminal artifact**

Require every generation capsule and evaluation history to verify and replay. Record only immutable roots, aggregate public-threshold metrics, absolute decisions, and stable high-level defect codes in the terminal receipt.

- [ ] **Step 4: Compute the publication gate**

Set `publication_ready: true` only when all three cases independently satisfy every Task 4 threshold and absolute `PASS`. Comparator performance cannot substitute for a failed Regulatory Harvest absolute gate.

- [ ] **Step 5: Stop after one suite**

Do not run a fourth case, replacement case, second candidate, or revised build. If `publication_ready` is false, write one bounded cross-case defect summary and return to the user for a new decision.

### Task 6: Prepare, but do not publish, the release candidate

**Files:**
- Modify only after three absolute passes: `README.md`
- Modify only after three absolute passes: `docs/evaluation.md`
- Modify only after three absolute passes: `docs/release-checklist.md`
- Modify only after three absolute passes: `CHANGELOG.md`
- Test: `tests/scripts/test_build_skill.py`
- Test: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: `publication_ready: true`, immutable suite receipt, verified archive, and clean-room audit.
- Produces: a public-safe, locally verified release candidate awaiting separate publication authorization.

- [ ] **Step 1: Write documentation tests first**

Require public docs to state, in substance:

```text
local and user-controlled storage
current-law research requires current authoritative sources
qualified attorney review is required before legal advice is delivered
gaps and uncertainty are preserved rather than invented away
the locked qualification suite is a bounded release gate, not a universal accuracy claim
```

Require the docs to omit private case identifiers, sources, paths, mappings, reports, scores, and answer text.

- [ ] **Step 2: Run the tests and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_build_skill.py tests/scripts/test_harvest_skill.py -q -k 'release or limitation or privacy or qualification'
```

- [ ] **Step 3: Update the release-facing documentation**

Document installation, the one-request attorney experience, supported source modes, user-controlled storage, known limitations, qualification methodology at a generic level, and the attorney-review boundary. `CHANGELOG.md` may state feature classes and public verification gates, but not private benchmark results.

- [ ] **Step 4: Run the complete public release gate**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
python3 scripts/audit_release.py --repo . --archive dist/regulatory-harvest-skill.zip --json
unzip -t dist/regulatory-harvest-skill.zip
shasum -a 256 dist/regulatory-harvest-skill.zip
```

Rebuild twice from clean Git snapshots after the documentation commit and require byte identity. Reinstall the final verified bytes recoverably and rerun full/portable smoke tests.

- [ ] **Step 5: Perform independent privacy and code review**

Review the complete implementation range, Git history, archive members, docs, fixture text, package metadata, and installed bytes. Resolve every Critical or Important finding with regression-first tests and rerun this task's entire gate.

- [ ] **Step 6: Commit only public-safe release preparation**

```bash
git add README.md docs/evaluation.md docs/release-checklist.md CHANGELOG.md tests/scripts/test_build_skill.py tests/scripts/test_harvest_skill.py
git diff --cached --check
git commit -m "docs: prepare regulatory harvest release candidate"
```

Do not add the private controller, qualification capsules, generation capsules, evaluation capsules, terminal receipt, defect reports, local backup, or archive unless repository policy and the user separately authorize that exact artifact.

- [ ] **Step 7: Return for the publication decision**

Report the exact commit, archive SHA-256, public test/lint/type/privacy results, installed-byte verification, and the single boolean `publication_ready`. Ask for separate authorization before any push, repository creation or visibility change, tag, hosted documentation, or GitHub release.

---

## Completion criteria

This plan is complete only when one of these mutually exclusive outcomes is recorded:

1. `STOPPED_CASE_NOT_READY`: a source record was not qualified; no candidate was generated.
2. `STOPPED_DESIGNATED_NOT_PASS`: the designated candidate did not satisfy the absolute gate; no full suite was run.
3. `SUITE_COMPLETE_NOT_READY`: the designated gate passed, the suite ran once, and fewer than three cases satisfied every absolute gate.
4. `RELEASE_CANDIDATE_READY`: all three cases passed every gate, all technical/privacy gates passed, and release artifacts are locally prepared but unpublished.

No outcome authorizes another cycle or public release automatically.
