# Evaluator Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Qualify source-only evaluation cases before generation, expose safe repairable preflight diagnostics, and provide a guarded submission path that cannot mutate a run after failed validation.

**Architecture:** Add a candidate-free qualification capsule beside the existing evaluation run, introduce a typed safe diagnostic boundary around response-contract failures, and add one atomic validate-and-submit API and CLI command. Preserve existing evaluation commands and histories; mirror every behavior in the standalone portable evaluator.

**Tech Stack:** Python 3.11+, Pydantic v2, canonical JSON/SHA-256 artifact graphs, pytest, Ruff, mypy, standard-library portable runtime.

## Global Constraints

- Evaluation reliability changes may not modify report generation, scoring thresholds, grading semantics, or comparator mappings.
- Existing evaluation and generation histories must remain replay-verifiable and byte-unchanged.
- Full and portable runtimes must emit byte-identical public requests, diagnostics, results, and hashes.
- Safe diagnostics may expose only fixed messages and identifiers already present in the pending request or rejected response.
- One role receives one initial response and at most two fresh-context mechanical repairs; the same diagnostic class twice stops the role.
- Integrity failures stop immediately; unfavorable substantive judgments are never retried.
- Public fixtures must be synthetic. No private case, report, response, score, path, or answer text may enter Git.
- Do not publish, push, open a pull request, or change repository visibility.

---

## File structure

- `src/regulatory_harvest/evaluation/attorney_contract.py`: controlled response-contract exception and safe diagnostic mapping.
- `src/regulatory_harvest/evaluation/attorney_qualification.py`: one-response, candidate-free source-record qualification capsule and replay verifier.
- `src/regulatory_harvest/evaluation/attorney_models.py`: typed diagnostic, guarded-submit, qualification input/state/manifest/receipt models.
- `src/regulatory_harvest/evaluation/attorney_workflow.py`: shared transition validation plus guarded submit.
- `src/regulatory_harvest/evaluation/attorney_ledger.py`: raise structured contract errors for known audit defects.
- `src/regulatory_harvest/evaluation/attorney_cli.py`: parse a qualification fixture from allowlisted local files.
- `scripts/attorney_eval_full.py`: full-runtime CLI routes.
- `scripts/attorney_eval_portable.py`: dependency-free mirrored models, qualification capsule, diagnostics, and guarded submit.
- `scripts/harvest_skill.py` and `scripts/harvest_portable.py`: expose the new commands through the installed skill.
- `assets/attorney-evaluation-qualification.template.json`: fictional candidate-free qualification input.
- `references/attorney-evaluation.md` and `SKILL.md`: qualification, safe-submit, and bounded-repair workflow.
- `tests/evaluation/test_attorney_qualification.py`: qualification capsule invariants and replay.
- `tests/evaluation/test_attorney_workflow.py`: diagnostic and guarded-transition behavior.
- `tests/scripts/test_attorney_eval_portable.py`: full/portable canonical parity.
- `tests/scripts/test_harvest_skill.py`: installed-surface CLI, no-mutation, and retry-contract tests.
- `tests/scripts/test_build_skill.py` and `scripts/skill-package-files.txt`: package allowlist and clean build.

### Task 1: Typed safe preflight diagnostics

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_contract.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_ledger.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Test: `tests/evaluation/test_attorney_ledger.py`
- Test: `tests/evaluation/test_attorney_workflow.py`

**Interfaces:**
- Produces: `ResponseContractCode`, `ResponseContractError`, and `safe_preflight_issue(error: Exception) -> EvaluationPreflightIssue`.
- Produces: `EvaluationPreflightIssue.related_ids: list[str]` and `EvaluationPreflightResult.diagnostic_fingerprint: str | None`.
- Consumes: existing `LedgerInconclusiveError`, `GradeInconclusiveError`, `JudgeOperation`, and canonical JSON helpers.

- [ ] **Step 1: Write failing diagnostic-contract tests**

Add focused tests that exercise the three known audit failure classes without using private text. Add this local tree-snapshot helper to `test_attorney_workflow.py`, and use the existing `synthetic_case` and `ScriptedJudge` builders to initialize the pending audit runs used below:

```python
def artifact_tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
```

```python
@pytest.mark.parametrize(
    ("audit_mutation", "expected_code", "related_ids"),
    [
        ("short_rationale", "EVALUATION_AUDIT_RATIONALE_INSUFFICIENT", ["audit-1"]),
        ("incomplete", "EVALUATION_AUDIT_INCOMPLETE", []),
        ("unknown_target", "EVALUATION_AUDIT_TARGET_UNKNOWN", ["missing-entry"]),
    ],
)
def test_preflight_returns_safe_operation_specific_diagnostic(
    initialized_audit_run: Path,
    audit_mutation: str,
    expected_code: str,
    related_ids: list[str],
) -> None:
    before = artifact_tree_bytes(initialized_audit_run)
    response = synthetic_audit_response(initialized_audit_run, audit_mutation)
    result = preflight_judge_response(initialized_audit_run, response)
    assert result.ok is False
    assert [issue.code for issue in result.issues] == [expected_code]
    assert result.issues[0].related_ids == related_ids
    assert result.diagnostic_fingerprint is not None
    assert artifact_tree_bytes(initialized_audit_run) == before
```

Also assert that messages contain no source quotation, local path, candidate ID, or report label.

- [ ] **Step 2: Run the focused tests and capture RED**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_ledger.py tests/evaluation/test_attorney_workflow.py -q -k 'safe_operation_specific or rationale_insufficient or audit_incomplete'
```

Expected: failures because preflight currently returns only `EVALUATION_RESPONSE_SEMANTIC_INVALID` and has no `related_ids` or diagnostic fingerprint.

- [ ] **Step 3: Add the controlled exception and diagnostic model**

Create a dependency-light contract module:

```python
class ResponseContractCode(StrEnum):
    SEMANTIC_INVALID = "EVALUATION_RESPONSE_SEMANTIC_INVALID"
    RESPONSE_INCOMPLETE = "EVALUATION_RESPONSE_INCOMPLETE"
    AUDIT_INCOMPLETE = "EVALUATION_AUDIT_INCOMPLETE"
    AUDIT_RATIONALE_INSUFFICIENT = "EVALUATION_AUDIT_RATIONALE_INSUFFICIENT"
    AUDIT_ACTION_INVALID = "EVALUATION_AUDIT_ACTION_INVALID"
    AUDIT_TARGET_UNKNOWN = "EVALUATION_AUDIT_TARGET_UNKNOWN"
    SOURCE_BINDING_INVALID = "EVALUATION_SOURCE_BINDING_INVALID"
    PROPOSED_ENTRY_INVALID = "EVALUATION_PROPOSED_ENTRY_INVALID"


class ResponseContractError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        code: ResponseContractCode = ResponseContractCode.SEMANTIC_INVALID,
        related_ids: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.related_ids = tuple(sorted(set(related_ids)))
```

Keep fixed public messages in one mapping. Extend `EvaluationPreflightIssue` with sorted unique `related_ids`, and add a diagnostic fingerprint that hashes only the canonical issue list, operation, and request fingerprint.

- [ ] **Step 4: Raise structured errors at the audit boundary**

Preserve `LedgerInconclusiveError` as the public exception type by making it inherit `ResponseContractError`. Update only deterministic response-contract failures, including:

```python
raise LedgerInconclusiveError(
    "audit rationale is insufficient",
    code=ResponseContractCode.AUDIT_RATIONALE_INSUFFICIENT,
    related_ids=[finding.dispute_id],
)
```

Map incomplete audits, invalid action cardinality, unknown targets, exact-source failures, and invalid proposed entries. Do not expose `str(error)` in preflight output. Unclassified failures retain the generic semantic-invalid code.

- [ ] **Step 5: Make preflight use the safe classifier**

Change the existing transition exception boundary to retain the exception object and produce one safe issue. Keep the existing explicit exception tuple so integrity errors remain outside this boundary:

```python
except (
    GradeInconclusiveError,
    LedgerInconclusiveError,
    ValidationError,
    ValueError,
    TypeError,
    KeyError,
) as error:
    issue = safe_preflight_issue(error)
    result = _preflight_result(request, issue=issue)
```

Integrity errors continue to propagate. Compute `diagnostic_fingerprint` only for failed results with a pending request; terminal no-pending remains a stable failure without a request fingerprint.

- [ ] **Step 6: Run focused and neighboring tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_ledger.py tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_models.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation tests/evaluation
.venv/bin/mypy src/regulatory_harvest/evaluation
```

Expected: all pass with unchanged terminal history fixtures.

- [ ] **Step 7: Commit Task 1**

```bash
git add src/regulatory_harvest/evaluation/attorney_contract.py src/regulatory_harvest/evaluation/attorney_models.py src/regulatory_harvest/evaluation/attorney_ledger.py src/regulatory_harvest/evaluation/attorney_workflow.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_ledger.py tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_models.py
git commit -m "feat: expose safe evaluator diagnostics"
```

### Task 2: Atomic guarded submission

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Test: `tests/evaluation/test_attorney_workflow.py`
- Test: `tests/evaluation/test_attorney_mutations.py`

**Interfaces:**
- Consumes: `EvaluationPreflightResult`, `EvaluationRunState`, `JudgeResponse`, and `_accepted_transition`.
- Produces: `GuardedSubmissionResult` and `guarded_submit_judge_response(run_dir: Path, response: JudgeResponse) -> GuardedSubmissionResult`.

- [ ] **Step 1: Write failing no-mutation and equivalence tests**

```python
def test_guarded_submit_rejects_without_mutating_run(initialized_run: Path) -> None:
    before = artifact_tree_bytes(initialized_run)
    result = guarded_submit_judge_response(initialized_run, invalid_audit_response())
    assert result.accepted is False
    assert result.state is None
    assert result.preflight.ok is False
    assert artifact_tree_bytes(initialized_run) == before


def test_guarded_submit_matches_existing_valid_submit(tmp_path: Path) -> None:
    guarded_run, explicit_run = twin_runs(tmp_path)
    response = valid_pending_response(guarded_run)
    guarded = guarded_submit_judge_response(guarded_run, response)
    explicit = submit_judge_response(explicit_run, response)
    assert guarded.accepted is True
    assert guarded.state == explicit
    assert artifact_tree_bytes(guarded_run) == artifact_tree_bytes(explicit_run)
```

Add a mutation test proving a transition-time integrity error remains exit-class 5 and writes no bytes.

- [ ] **Step 2: Run the focused tests and capture RED**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_mutations.py -q -k 'guarded_submit'
```

Expected: import or attribute failures because the guarded API does not exist.

- [ ] **Step 3: Add the guarded result model**

Define the result after `EvaluationRunState`:

```python
class GuardedSubmissionResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    accepted: bool
    preflight: EvaluationPreflightResult
    state: EvaluationRunState | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.accepted != self.preflight.ok:
            raise ValueError("guarded submission acceptance must match preflight")
        if self.accepted != (self.state is not None):
            raise ValueError("accepted guarded submission requires state")
        return self
```

- [ ] **Step 4: Implement one-storage guarded validation and commit**

Factor a private `_preflight_in_storage(storage, manifest, envelope, pending, request, response)` helper that returns both the public preflight result and the already-calculated transition. `guarded_submit_judge_response` opens and verifies storage once, returns without writes when the result is false, and commits exactly that transition when true. Do not calculate a second legal transition after a successful validation.

```python
def guarded_submit_judge_response(
    run_dir: Path,
    response: JudgeResponse,
) -> GuardedSubmissionResult:
    response, response_bytes = _model_bytes(response, JudgeResponse)
    with _open_run_storage(run_dir) as storage:
        preflight, context = _preflight_in_storage(storage, response)
        if not preflight.ok:
            storage.assert_root_identity()
            return GuardedSubmissionResult(accepted=False, preflight=preflight)
        state = _commit_validated_response(storage, context, response, response_bytes)
        storage.assert_root_identity()
        return GuardedSubmissionResult(accepted=True, preflight=preflight, state=state)
```

Keep `preflight_judge_response` and `submit_judge_response` behavior unchanged by routing them through the same private helpers.

- [ ] **Step 5: Run focused, replay, and mutation tests**

```bash
.venv/bin/pytest tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_mutations.py tests/evaluation/test_attorney_artifacts.py -q
```

Expected: all pass; explicit and guarded valid run trees are byte-identical.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/regulatory_harvest/evaluation/attorney_models.py src/regulatory_harvest/evaluation/attorney_workflow.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_mutations.py
git commit -m "feat: add guarded evaluator submission"
```

### Task 3: Candidate-free source-record qualification capsule

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_qualification.py`
- Create: `tests/evaluation/test_attorney_qualification.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_admission.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Create: `assets/attorney-evaluation-qualification.template.json`

**Interfaces:**
- Produces: `QualificationCase`, `QualificationState`, `QualificationReceipt`, and `QualificationVerification`.
- Produces: `initialize_case_qualification`, `next_qualification_request`, `submit_case_qualification`, `resume_case_qualification`, and `verify_case_qualification`.
- Consumes: the existing five admission checks, `EvaluationSource`, `RequestedAuthority`, `CaseAdmissionJudgment`, and canonical artifact helpers.
- Enforces: authority alignment, operative text, declared-date currentness, language resolution, and a candidate-free source-parity contract.

- [ ] **Step 1: Write candidate-free qualification RED tests**

Cover exact source-byte binding, readiness outcomes, immutable single response, and replay:

```python
def test_candidate_free_qualification_seals_admitted_source_record(tmp_path: Path) -> None:
    case = qualification_case(currentness_source=True)
    state = initialize_case_qualification(case, tmp_path, nonce_hex="1" * 64)
    request = next_qualification_request(tmp_path)
    assert state.status == "awaiting-judgment"
    assert request.payload["sources"]
    assert "candidates" not in request.payload
    receipt = submit_case_qualification(tmp_path, admitted_judgment(request))
    assert receipt.readiness.status.value == "ADMITTED"
    assert verify_case_qualification(tmp_path).valid is True


def test_unready_qualification_is_terminal_without_generation(tmp_path: Path) -> None:
    case = qualification_case(currentness_source=False)
    request = initialize_and_next(case, tmp_path)
    receipt = submit_case_qualification(tmp_path, failed_currentness_judgment(request))
    assert receipt.readiness.status.value == "CASE_INVALID"
    assert next_qualification_request(tmp_path) is None
```

Add tamper tests for the input, request, judgment, manifest, and receipt, plus a path-containment test.

- [ ] **Step 2: Run the new tests and capture RED**

```bash
.venv/bin/pytest tests/evaluation/test_attorney_qualification.py -q
```

Expected: collection failure because the qualification models and functions do not exist.

- [ ] **Step 3: Define candidate-free models**

Use the same legal fields as `AttorneyEvaluationCase`, without reports or generation provenance:

```python
class QualificationCase(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    mode: EvaluationMode
    question: str
    jurisdiction: str
    as_of: date
    requested_authorities: list[RequestedAuthority] = Field(min_length=1)
    sources: list[EvaluationSource] = Field(min_length=1)


class QualificationReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_fingerprint: str = Field(pattern=_HASH_PATTERN)
    source_record_fingerprint: str = Field(pattern=_HASH_PATTERN)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judgment_fingerprint: str = Field(pattern=_HASH_PATTERN)
    readiness: CaseReadiness
    receipt_fingerprint: str = Field(pattern=_HASH_PATTERN)
```

Define a minimal manifest with allowlisted artifact records, one pending/completed call, immutable state (`awaiting-judgment`, `qualified`, or `case-invalid`), and a root hash.

- [ ] **Step 4: Extract shared admission projection and adjudication**

Refactor candidate-independent logic in `attorney_admission.py` behind these exact signatures:

- `build_source_record(case: AttorneyEvaluationCase | QualificationCase) -> dict[str, object]`
- `build_admission_request(source_record: Mapping[str, object]) -> JudgeRequest`
- `adjudicate_source_record(*, case_fingerprint: str, source_ids: set[str], deterministic_issues: Sequence[EvaluationIssue], request: JudgeRequest, judgment: CaseAdmissionJudgment) -> CaseReadiness`

Existing `build_admission_packet` and `adjudicate_admission` remain public-compatible wrappers. Qualification excludes candidate-provenance parity checks and client facts. Its `SOURCE_PARITY` check establishes the candidate-free source-parity contract: the frozen record is the one common evidence universe designated for both later candidates. Evaluation initialization still verifies each actual candidate's provenance against that exact root.

- [ ] **Step 5: Implement the one-response qualification capsule**

Store only canonical `qualification-case.json`, `admission-request.json`, `admission-response.json`, `qualification-receipt.json`, and `manifest.json`. Initialization refuses an existing nonempty target. Qualification submission validates the exact pending fingerprint before writing: a malformed response returns one bounded safe diagnostic and writes nothing; the first valid response seals either admitted or case-invalid readiness and all later submissions are refused. Verification reconstructs every fingerprint and the root.

- [ ] **Step 6: Add the fictional template**

Create a synthetic current-law example with two fictional public-authority text files, one operative source and one status/currentness source. Every path is relative, every sentinel is `__REPLACE__`, and the template contains no real client or local path.

- [ ] **Step 7: Run qualification, admission, and artifact tests**

```bash
.venv/bin/pytest tests/evaluation/test_attorney_qualification.py tests/evaluation/test_attorney_admission.py tests/evaluation/test_attorney_artifacts.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation tests/evaluation/test_attorney_qualification.py
.venv/bin/mypy src/regulatory_harvest/evaluation
```

- [ ] **Step 8: Commit Task 3**

```bash
git add src/regulatory_harvest/evaluation/attorney_qualification.py src/regulatory_harvest/evaluation/attorney_models.py src/regulatory_harvest/evaluation/attorney_admission.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_qualification.py assets/attorney-evaluation-qualification.template.json
git commit -m "feat: qualify evaluation sources before generation"
```

### Task 4: Full and portable CLI parity

**Files:**
- Modify: `scripts/attorney_eval_full.py`
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_skill.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Test: `tests/scripts/test_attorney_eval_portable.py`
- Test: `tests/scripts/test_harvest_skill.py`
- Test: `tests/scripts/test_harvest_portable.py`

**Interfaces:**
- Consumes: Task 1 diagnostics, Task 2 guarded submit, and Task 3 qualification capsule.
- Produces CLI commands: `eval-submit-safe`, `eval-qualify-init`, `eval-qualify-next`, `eval-qualify-submit`, `eval-qualify-status`, and `eval-qualify-verify`.

- [ ] **Step 1: Write CLI and byte-parity RED tests**

Add table-driven tests that run both installed surfaces and compare return codes and exact stdout bytes for:

```python
COMMANDS = (
    "eval-submit-safe",
    "eval-qualify-init",
    "eval-qualify-next",
    "eval-qualify-submit",
    "eval-qualify-status",
    "eval-qualify-verify",
)
```

Assert failed guarded submission leaves both run trees byte-identical to their pre-call snapshots; successful guarded submission matches existing explicit submission. Assert all qualification artifacts and roots match full versus portable.

- [ ] **Step 2: Run CLI tests and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_portable.py -q -k 'qualify or submit_safe or safe_diagnostic'
```

Expected: parser-command failures and missing portable functions.

- [ ] **Step 3: Add full CLI routes**

Use the existing response size, depth, canonical JSON, exit-code, and path guards. `eval-submit-safe` emits the complete `GuardedSubmissionResult`; it exits `0` only when accepted, `2` for a safe contract refusal, and `5` for integrity failure. Qualification commands use a physical absolute run path and canonical JSON only.

- [ ] **Step 4: Mirror the complete implementation in the standalone evaluator**

Do not import package-only dependencies. Mirror controlled enums, validation, canonical hashes, artifact layouts, and fixed messages. Add an explicit parity fixture for every diagnostic code, including malformed raw dictionaries and validation-bypassing values.

- [ ] **Step 5: Route commands through both skill runners**

Update the subparser command lists in `harvest_skill.py` and `harvest_portable.py`. Keep legacy command names and behavior unchanged.

- [ ] **Step 6: Run exact parity and neighboring suites**

```bash
.venv/bin/pytest tests/evaluation/test_attorney_qualification.py tests/evaluation/test_attorney_workflow.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q
```

- [ ] **Step 7: Commit Task 4**

```bash
git add scripts/attorney_eval_full.py scripts/attorney_eval_portable.py scripts/harvest_skill.py scripts/harvest_portable.py src/regulatory_harvest/evaluation/attorney_cli.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py
git commit -m "feat: expose guarded evaluator controls"
```

### Task 5: Installed-skill workflow and bounded repair contract

**Files:**
- Modify: `SKILL.md`
- Modify: `references/attorney-evaluation.md`
- Modify: `assets/attorney-evaluation-response.template.json`
- Test: `tests/scripts/test_harvest_skill.py`
- Test: `tests/scripts/test_build_skill.py`

**Interfaces:**
- Consumes: all new evaluator CLI commands.
- Produces: one attorney-hidden sequence: qualify sources, generate, evaluate with guarded submission, repair at most twice, verify terminal artifacts.

- [ ] **Step 1: Add failing static and behavioral tests**

Require the installed instruction surfaces to say, in substance and testable exact phrases:

```text
qualify every locked case before generating a candidate
use eval-submit-safe for every evaluator response
one initial response and at most two mechanical repairs
stop when the same diagnostic code occurs twice
never retry an unfavorable substantive judgment
```

Add a synthetic controller trace test with three responses: first rationale failure, second same rationale failure, and an unused third response. Assert only two are consumed and no invalid response enters the evaluation run.

- [ ] **Step 2: Run the skill tests and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py -q -k 'qualification or bounded_repair or submit_safe'
```

- [ ] **Step 3: Update the attorney-hidden workflow**

Document the exact command order, safe diagnostic handling, truthfulness of fresh-context labels, and terminal verification. The user-facing journey remains one request; do not expose commands, JSON, role queues, or retry mechanics unless asked.

Clarify that qualification readiness is not a report-quality PASS and that changing source bytes creates a new versioned case.

- [ ] **Step 4: Validate skill behavior and package tests**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py -q
.venv/bin/pytest tests/skill/test_skill_package.py -q
```

- [ ] **Step 5: Commit Task 5**

```bash
git add SKILL.md references/attorney-evaluation.md assets/attorney-evaluation-response.template.json tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py
git commit -m "docs: bound evaluator repair workflow"
```

### Task 6: Package, replay, and independent review gate

**Files:**
- Modify: `scripts/skill-package-files.txt`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `docs/evaluation.md`
- Modify: `docs/release-checklist.md`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: one reproducible package containing qualification and guarded evaluator support, with no publication action.

- [ ] **Step 1: Add new files to the explicit package manifest**

Add the new production module and qualification template in sorted order. Extend package tests to require their presence in both ZIP builds and clean extraction.

- [ ] **Step 2: Run focused evaluator verification**

```bash
.venv/bin/pytest tests/evaluation/test_attorney_admission.py tests/evaluation/test_attorney_qualification.py tests/evaluation/test_attorney_ledger.py tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_mutations.py tests/evaluation/test_attorney_artifacts.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py -q
```

- [ ] **Step 3: Run static and full verification**

```bash
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
git diff --check
```

Expected: all configured checks pass, with only an already-documented unrelated skip if one remains.

- [ ] **Step 4: Build twice from one clean committed snapshot**

Use the repository's existing build command from `tests/scripts/test_build_skill.py`. Assert identical file count, byte length, and SHA-256 for both archives. Extract one archive and run full and `python3 -I -S` portable `--help` smoke tests for all new commands.

- [ ] **Step 5: Perform an adversarial review**

Review these exact risks before completion:

- safe diagnostics leaking source text through exception messages;
- qualification accepting a source record with missing currentness evidence;
- guarded submission writing any byte after failed validation;
- full/portable diagnostic or root divergence;
- retry instructions permitting a fourth attempt;
- replay verification accepting a changed qualification artifact; and
- private paths or case markers entering the package.

Fix every Critical or Important finding with a new failing regression before changing production code.

- [ ] **Step 6: Update public evaluation documentation**

Document source qualification, guarded submission, bounded repairs, and the distinction between case readiness and report PASS. Do not include private cases, scores, or local paths.

- [ ] **Step 7: Commit Task 6**

```bash
git add scripts/skill-package-files.txt tests/scripts/test_build_skill.py docs/evaluation.md docs/release-checklist.md
git commit -m "docs: package evaluator reliability controls"
```

- [ ] **Step 8: Record the evaluator reliability completion gate**

Record the exact commits, commands, counts, archive hash, and any deferred Minor finding in the task progress artifact selected at execution time. Do not initialize or run a private legal evaluation in this plan; that begins only after the atomic-coverage plan also passes.
