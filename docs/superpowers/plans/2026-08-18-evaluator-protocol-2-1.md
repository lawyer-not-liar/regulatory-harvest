# Evaluator Protocol 2.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Protocol 2.1 with one-dispute referee fragments, bounded grade fragments, contested requirements, deterministic outcome sensitivity, exact replay compatibility, and a verified public gate before any private readiness run.

**Architecture:** Keep Protocol 2.0 source-review and source-audit semantic types, but add a separate Protocol 2.1 request, manifest, artifact, workflow, and aggregation surface. Deterministic code splits disputes and grades into independently sealed fragments, compiles common and contested requirements, and calculates whether unresolved legal uncertainty changes the disposition. Protocols 1.3 and 2.0 remain replay-only and byte-stable.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, standard-library portable mirror, Ruff, mypy, canonical UTF-8 JSON, SHA-256 artifact binding.

**Spec:** `docs/superpowers/specs/2026-08-18-evaluator-protocol-2-1-design.md`

## Global Constraints

- Protocol 2.1 is a distinct new-run protocol; never relabel or rewrite Protocol 1.3 or 2.0 artifacts.
- The source reviewer and source auditor contracts remain unchanged.
- Each source-referee request contains exactly one dispute and runs in a fresh context.
- Ordinary grade batches contain at most five requirements; each contested requirement is graded individually.
- Two grader lanes remain isolated from one another; every fragment request is evidence-complete.
- A valid substantive `unresolved` judgment continues to grading; a second mechanical refusal stops as `INCONCLUSIVE_MECHANICAL`.
- Outcome sensitivity, not unresolved-dispute count, determines substantive `INCONCLUSIVE`.
- Deterministic code owns identifiers, ordering, envelopes, fingerprints, artifacts, aggregation, and final sensitivity calculations.
- Rejected response content is never committed, reused, summarized, or supplied to a repair context.
- Full and isolated portable behavior must match exactly before Protocol 2.1 can become the new-run default.
- No private readiness run, publication action, maturity claim, or performance claim is authorized by implementation completion alone.

## File Structure

New full-runtime modules:

- `src/regulatory_harvest/evaluation/attorney_v21_models.py`: Protocol 2.1 value types, request/response models, fragment records, contested baseline, manifest, state, and terminal result.
- `src/regulatory_harvest/evaluation/attorney_v21_compiler.py`: deterministic dispute packets, referee aggregation, common/contested baseline compilation, and fingerprinting.
- `src/regulatory_harvest/evaluation/attorney_v21_requests.py`: source, single-dispute referee, ordinary-grade batch, contested-grade, and retry request builders.
- `src/regulatory_harvest/evaluation/attorney_v21_rubric.py`: lane aggregation, two-grader reconciliation, branch scoring, and outcome-sensitivity calculation.
- `src/regulatory_harvest/evaluation/attorney_v21_artifacts.py`: Protocol 2.1 storage initialization, atomic transitions, verifier, inventory grammar, and replay loader.
- `src/regulatory_harvest/evaluation/attorney_v21_workflow.py`: bounded Protocol 2.1 controller and public Python API.
- `src/regulatory_harvest/evaluation/attorney_protocol.py`: protocol detection shared by full CLI and replay loaders.

New focused tests mirror those modules under `tests/evaluation/`.

Existing files changed only at integration boundaries:

- `src/regulatory_harvest/evaluation/__init__.py`
- `src/regulatory_harvest/evaluation/attorney_cli.py`
- `scripts/attorney_eval_full.py`
- `scripts/harvest_skill.py`
- `scripts/attorney_eval_portable.py`
- `scripts/harvest_portable.py`
- `scripts/skill-package-files.txt`
- `README.md`
- `SKILL.md`
- `docs/evaluation.md`
- `references/attorney-evaluation.md`
- package, CLI, portable, and skill tests named in Tasks 6-9

The portable mirror remains in `scripts/attorney_eval_portable.py` because it must run under `python3 -I -S`; do not import package modules from that path.

---

### Task 1: Protocol 2.1 Foundation Models

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v21_models.py`
- Create: `tests/evaluation/test_attorney_v21_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: stable `SemanticPassage`, `SemanticProposal`, `AuditConcernV2`, `MaterialDisputeV2`, `CanonicalRequirementV2`, `CanonicalRelationshipV2`, `RequirementKindV2`, `ImportanceV2`, and strict JSON helpers from `attorney_v2_models.py`.
- Produces: `PROTOCOL_V21`, `SourceReviewV21`, `SourceAuditV21`, `EvaluatorRequestV21`, `EvaluatorResponseV21`, `RefereeDisputeV21`, `RefereeDecisionV21`, `AcceptedRefereeFragmentV21`, `RefereeAggregateV21`, `ContestedRequirementV21`, `CanonicalBaselineV21`, `OrdinaryGradeBatchV21`, `OrdinaryGradeFragmentV21`, `ContestedGradeFragmentV21`, `GraderAggregateV21`, `ReconciledGradeV21`, `RubricV21`, `SensitivityRecordV21`, `EvaluationCallRecordV21`, `EvaluationManifestV21`, `EvaluationRunStateV21`, and `EvaluationResultV21`.

- [ ] **Step 1: Write strict model tests first**

Add tests that require literal protocol `2.1`, immutable nested snapshots, bounded JSON size/depth, one referee determination, conditional unresolved reason codes, known controller-issued evidence references, at-most-five ordinary requirements, one contested requirement per fragment, two distinct grader lanes, and exact phase/status correspondence.

```python
def test_referee_unresolved_requires_substantive_reason() -> None:
    with pytest.raises(ValidationError):
        RefereeDecisionV21(
            schema_version="2.1",
            decision="unresolved",
            unresolved_reason=None,
            evidence_refs=["EVID-0001"],
            rationale="The retained authorities conflict.",
        )


def test_ordinary_grade_batch_is_bounded() -> None:
    with pytest.raises(ValidationError):
        OrdinaryGradeBatchV21(
            batch_ref="GB-A-1-0001",
            requirement_ids=[f"REQ-{index:04d}" for index in range(6)],
        )
```

- [ ] **Step 2: Run the model test and confirm RED**

Run:

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v21_models.py -q
```

Expected: collection fails because `attorney_v21_models` does not exist.

- [ ] **Step 3: Implement the minimum strict model surface**

Use explicit literals and discriminated fragment types. Key definitions must follow this shape:

```python
PROTOCOL_V21: Literal["2.1"] = "2.1"


class RefereeUnresolvedReasonV21(StrEnum):
    SOURCE_AMBIGUITY = "SOURCE_AMBIGUITY"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    SOURCE_GAP = "SOURCE_GAP"
    BOTH_POSITIONS_UNSUPPORTED = "BOTH_POSITIONS_UNSUPPORTED"


class RefereeDecisionV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    unresolved_reason: RefereeUnresolvedReasonV21 | None = None
    evidence_refs: tuple[str, ...]
    rationale: str


class AcceptedRefereeFragmentV21(V21StrictModel):
    dispute_id: str
    decision: RefereeDecisionV21
    response_fingerprint: str


class OrdinaryGradeBatchV21(V21StrictModel):
    batch_ref: str
    requirement_ids: tuple[str, ...] = Field(min_length=1, max_length=5)
```

Validators must require `unresolved_reason` only for `unresolved`, forbid it for accepted alternatives, reject duplicate/unknown references through explicit validation context, and deep-freeze request/response payloads. Re-export only the stable public Protocol 2.1 API from `evaluation/__init__.py`.

- [ ] **Step 4: Add adversarial construction tests**

Cover raw dicts, `model_construct`, cycles, unhashable references, duplicate evidence refs, six-item batches, forged lane labels, extra keys, blank rationale, and mutation attempts after construction.

- [ ] **Step 5: Run focused and neighboring model tests**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_models.py \
  tests/evaluation/test_attorney_v2_models.py \
  tests/evaluation/test_attorney_models.py -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_v21_models.py \
  tests/evaluation/test_attorney_v21_models.py
PYTHONPATH=src ../../.venv/bin/mypy \
  src/regulatory_harvest/evaluation/attorney_v21_models.py
```

Expected: all selected tests, Ruff, and mypy pass.

- [ ] **Step 6: Commit the model contract**

```bash
git add src/regulatory_harvest/evaluation/attorney_v21_models.py \
  src/regulatory_harvest/evaluation/__init__.py \
  tests/evaluation/test_attorney_v21_models.py
git diff --cached --check
git commit -m "feat: define evaluator protocol 2.1 models"
```

### Task 2: Single-Dispute Referee and Contested Baseline Compiler

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v21_compiler.py`
- Create: `src/regulatory_harvest/evaluation/attorney_v21_requests.py`
- Create: `tests/evaluation/test_attorney_v21_compiler.py`
- Create: `tests/evaluation/test_attorney_v21_requests.py`

**Interfaces:**
- Consumes: Task 1 models; `index_review`, `material_disputes`, and `resolve_exact_passage` from `attorney_v2_compiler.py`; field-equivalent Protocol 2.1 source-review and source-audit wrappers.
- Produces: `build_referee_disputes`, `build_source_review_request_v21`, `build_source_audit_request_v21`, `build_source_referee_fragment_request`, `validate_referee_fragment`, `aggregate_referee_decisions`, `compile_baseline_v21`, and `mechanical_retry_request_v21`.

- [ ] **Step 1: Write failing compiler and request tests**

Require stable dispute order, one dispute per referee request, controller-issued `EVID-####` references, no dispute ID in the inner response schema, exact source passage resolution, mixed reviewer/auditor decisions, and preservation of both alternatives for substantive unresolved.

```python
def test_referee_request_contains_exactly_one_dispute() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit_with_two_concerns())
    first = build_source_referee_fragment_request(envelope(), disputes[0])
    assert len(first.payload["material_disputes"]) == 1
    assert "dispute_id" not in first.json_schema["properties"]


def test_unresolved_compiles_contested_requirement() -> None:
    aggregate = referee_aggregate(decision="unresolved")
    baseline = compile_baseline_v21(
        envelope(), review(), audit(), aggregate
    )
    assert len(baseline.contested_requirements) == 1
    assert baseline.contested_requirements[0].reviewer_alternative is not None
    assert baseline.contested_requirements[0].auditor_alternative is not None
```

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_compiler.py \
  tests/evaluation/test_attorney_v21_requests.py -q
```

Expected: collection fails for both absent modules.

- [ ] **Step 3: Implement deterministic dispute packets**

Resolve all source passages before issuing a referee request. Assign evidence refs from canonical source ID, start, end, and quote ordering. A response selects only refs already present in its one request.

```python
def build_referee_disputes(
    envelope: CaseEnvelope,
    review: SourceReviewV21,
    audit: SourceAuditV21,
) -> tuple[RefereeDisputeV21, ...]:
    v2_review, v2_audit = _v2_semantic_snapshots(review, audit)
    indexed = index_review(v2_review)
    disputes = material_disputes(v2_review, v2_audit)
    return tuple(_resolve_dispute(envelope, indexed, dispute) for dispute in disputes)
```

- [ ] **Step 4: Implement request builders and retry identity**

`build_source_review_request_v21` and `build_source_audit_request_v21` must preserve the Protocol 2.0 semantic fields while requiring literal inner schema version `2.1`. Deterministic adapters may construct validated Protocol 2.0 semantic snapshots for reuse by stable compiler primitives; evaluator roles never perform that conversion. `mechanical_retry_request_v21` must reconstruct the exact original payload/schema and change only the controller-issued request fingerprint/attempt binding defined by the manifest.

- [ ] **Step 5: Implement referee aggregation and baseline compilation**

```python
def aggregate_referee_decisions(
    disputes: tuple[RefereeDisputeV21, ...],
    fragments: tuple[AcceptedRefereeFragmentV21, ...],
) -> RefereeAggregateV21:
    if tuple(item.dispute_id for item in disputes) != tuple(
        item.dispute_id for item in fragments
    ):
        raise CompilationError("REFEREE_FRAGMENT_COVERAGE_INVALID")
    return _sealed_referee_aggregate(disputes, fragments)


def compile_baseline_v21(
    envelope: CaseEnvelope,
    review: SourceReviewV21,
    audit: SourceAuditV21,
    aggregate: RefereeAggregateV21,
) -> CanonicalBaselineV21:
    common, contested = _apply_fragmented_decisions(review, audit, aggregate)
    return _seal_v21_baseline(envelope, common, contested)
```

The compiler must reject missing, duplicate, swapped, forged, or cross-case fragments. It must not choose an alternative for `unresolved`.

- [ ] **Step 6: Run compiler/request regression and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_compiler.py \
  tests/evaluation/test_attorney_v21_requests.py \
  tests/evaluation/test_attorney_v2_compiler.py \
  tests/evaluation/test_attorney_v2_requests.py -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_v21_compiler.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py \
  tests/evaluation/test_attorney_v21_compiler.py \
  tests/evaluation/test_attorney_v21_requests.py
PYTHONPATH=src ../../.venv/bin/mypy \
  src/regulatory_harvest/evaluation/attorney_v21_compiler.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py
```

- [ ] **Step 7: Commit referee and compiler support**

```bash
git add src/regulatory_harvest/evaluation/attorney_v21_compiler.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py \
  tests/evaluation/test_attorney_v21_compiler.py \
  tests/evaluation/test_attorney_v21_requests.py
git diff --cached --check
git commit -m "feat: fragment evaluator source adjudication"
```

### Task 3: Bounded Grading and Outcome Sensitivity

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v21_rubric.py`
- Create: `tests/evaluation/test_attorney_v21_rubric.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_v21_requests.py`
- Modify: `tests/evaluation/test_attorney_v21_requests.py`

**Interfaces:**
- Consumes: Task 1 baseline/fragment models and Task 2 compiled `CanonicalBaselineV21`.
- Produces: `ordinary_grade_batches`, `build_ordinary_grade_request_v21`, `build_contested_grade_request_v21`, `validate_grade_fragment_v21`, `aggregate_grader_lane`, `reconcile_grader_lanes`, and `evaluate_outcome_sensitivity`.

- [ ] **Step 1: Write failing batch and sensitivity tests**

Cover deterministic batches of 5/5/remainder, individual contested requests, lane A/B isolation, complete coverage, stable PASS, stable FAIL, outcome-changing INCONCLUSIVE, insufficient-evidence INCONCLUSIVE, and many outcome-stable contested requirements.

```python
def test_ordinary_batches_are_stable_and_never_exceed_five() -> None:
    batches = ordinary_grade_batches(baseline_with_requirements(12), "A", 1)
    assert [len(batch.requirement_ids) for batch in batches] == [5, 5, 2]


def test_outcome_sensitivity_ignores_raw_unresolved_count() -> None:
    record = evaluate_outcome_sensitivity(
        baseline_with_contested(10),
        reconciled_findings_with_same_branch_result("PASS"),
        RUBRIC_V21,
    )
    assert record.absolute_disposition == "PASS"
    assert record.outcome_determinative_contested_ids == ()
```

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_rubric.py \
  tests/evaluation/test_attorney_v21_requests.py -q
```

Expected: missing grading functions and rubric module.

- [ ] **Step 3: Implement deterministic grade inventories and requests**

```python
def ordinary_grade_batches(
    baseline: CanonicalBaselineV21,
    anonymous_label: Literal["A", "B"],
    grader_lane: Literal[1, 2],
) -> tuple[OrdinaryGradeBatchV21, ...]:
    ids = tuple(item.requirement_id for item in baseline.requirements)
    return tuple(_batch(ids[index : index + 5], anonymous_label, grader_lane, index // 5)
                 for index in range(0, len(ids), 5))
```

Ordinary request payloads carry only their requirement subset plus the shared rubric/report/source context. Contested requests carry exactly one contested requirement and both alternatives.

- [ ] **Step 4: Implement fragment validation and lane aggregation**

Validate exact report passages, report hash, baseline hash, anonymous label, grader lane, batch ref, requirement coverage, and contested alternative coverage. Aggregate only when every deterministic batch/contested item exists exactly once.

- [ ] **Step 5: Implement deterministic sensitivity calculation**

```python
def evaluate_outcome_sensitivity(
    baseline: CanonicalBaselineV21,
    reconciliation: ReconciledGradeV21,
    rubric: RubricV21,
) -> SensitivityRecordV21:
    branch_results = tuple(
        _score_both_alternatives(item, reconciliation, rubric)
        for item in baseline.contested_requirements
    )
    changing = tuple(
        result.contested_requirement_id
        for result in branch_results
        if result.reviewer_disposition != result.auditor_disposition
    )
    return _seal_sensitivity(branch_results, changing, reconciliation, rubric)
```

If `changing` is nonempty, return `INCONCLUSIVE` with
`OUTCOME_SENSITIVE_BASELINE_DISPUTE`. If neither branch is meaningfully gradable,
return `BASELINE_EVIDENCE_INSUFFICIENT`. Otherwise preserve the stable reconciled
PASS or FAIL.

- [ ] **Step 6: Run focused, legacy rubric, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_rubric.py \
  tests/evaluation/test_attorney_v21_requests.py \
  tests/evaluation/test_attorney_v2_rubric.py -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_v21_rubric.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py \
  tests/evaluation/test_attorney_v21_rubric.py \
  tests/evaluation/test_attorney_v21_requests.py
PYTHONPATH=src ../../.venv/bin/mypy \
  src/regulatory_harvest/evaluation/attorney_v21_rubric.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py
```

- [ ] **Step 7: Commit bounded grading**

```bash
git add src/regulatory_harvest/evaluation/attorney_v21_rubric.py \
  src/regulatory_harvest/evaluation/attorney_v21_requests.py \
  tests/evaluation/test_attorney_v21_rubric.py \
  tests/evaluation/test_attorney_v21_requests.py
git diff --cached --check
git commit -m "feat: grade evaluator requirements in bounded fragments"
```

### Task 4: Protocol Detection, Storage, and Replay Verification

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_protocol.py`
- Create: `src/regulatory_harvest/evaluation/attorney_v21_artifacts.py`
- Create: `tests/evaluation/test_attorney_v21_artifacts.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_v2_artifacts.py`
- Modify: `tests/evaluation/test_attorney_v2_artifacts.py`

**Interfaces:**
- Consumes: existing secure `_RunStorage`, canonical JSON bounds, and artifact records; Task 1 manifest/result types.
- Produces: `detect_evaluation_protocol`, `initialize_v21_run_storage`, `commit_v21_transition`, `preflight_v21_response`, `verify_v21_run`, and `load_verified_v21_run`.

- [ ] **Step 1: Write failing protocol and artifact grammar tests**

Require exact detection of 1.3, 2.0, and 2.1; unknown fail-closed behavior; partial referee/grade histories; exact pending request; accepted fragment inventory; no duplicate/skipped fragments; aggregate and sensitivity bindings; and terminal mechanical states without rejected response artifacts.

```python
def test_protocol_detector_preserves_all_recognized_generations(tmp_path: Path) -> None:
    assert detect_evaluation_protocol(v13_run(tmp_path)) == "1.3"
    assert detect_evaluation_protocol(v20_run(tmp_path)) == "2.0"
    assert detect_evaluation_protocol(v21_run(tmp_path)) == "2.1"


def test_verifier_rejects_swapped_referee_fragment(tmp_path: Path) -> None:
    run = completed_referee_inventory(tmp_path)
    swap_bytes(run / "responses/referee-D0001.json", run / "responses/referee-D0002.json")
    assert not verify_v21_run(run).valid
```

- [ ] **Step 2: Run artifact tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v2_artifacts.py -q
```

- [ ] **Step 3: Extract protocol detection without changing 2.0 bytes**

Move only manifest-version detection into `attorney_protocol.py`. Keep a compatibility import in `attorney_v2_artifacts.py` so existing callers and tests continue to resolve the old symbol.

```python
def detect_evaluation_protocol(run_dir: Path) -> str:
    manifest = _bounded_manifest_version(run_dir)
    if manifest not in {"1.3", "2.0", "2.1"}:
        raise EvaluationIntegrityError("EVALUATION_PROTOCOL_UNSUPPORTED")
    return manifest
```

- [ ] **Step 4: Implement the Protocol 2.1 verifier and atomic transition API**

The verifier must reconstruct the legal call-history grammar, fragment inventories, expected batch order, aggregate fingerprints, baseline fingerprint, grader-lane aggregates, sensitivity record, and terminal result. Reuse secure descriptor-anchored storage; do not add a second filesystem primitive.

```python
def commit_v21_transition(
    run_dir: Path,
    expected_manifest_fingerprint: str,
    files: Mapping[str, bytes],
    successor: EvaluationManifestV21,
) -> None:
    storage = _RunStorage(run_dir)
    current, _ = _verify_or_raise(storage)
    if current.manifest_fingerprint != expected_manifest_fingerprint:
        raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
    _commit_with_rollback(storage, files, successor)
```

- [ ] **Step 5: Add rollback, race, and malformed-tree controls**

Test response-write failure, manifest-write failure, same-byte races, symlink/FIFO/empty-directory inventory, deep/cyclic JSON, malformed manifest state, unbound extra artifacts, result-shaped junk, partial aggregates, and exact no-write rollback.

- [ ] **Step 6: Run artifact, storage, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v2_artifacts.py \
  tests/evaluation/test_attorney_artifacts.py -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_protocol.py \
  src/regulatory_harvest/evaluation/attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v21_artifacts.py
PYTHONPATH=src ../../.venv/bin/mypy \
  src/regulatory_harvest/evaluation/attorney_protocol.py \
  src/regulatory_harvest/evaluation/attorney_v21_artifacts.py
```

- [ ] **Step 7: Commit storage and replay support**

```bash
git add src/regulatory_harvest/evaluation/attorney_protocol.py \
  src/regulatory_harvest/evaluation/attorney_v21_artifacts.py \
  src/regulatory_harvest/evaluation/attorney_v2_artifacts.py \
  tests/evaluation/test_attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v2_artifacts.py
git diff --cached --check
git commit -m "feat: seal evaluator protocol 2.1 fragments"
```

### Task 5: Bounded Protocol 2.1 Workflow

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v21_workflow.py`
- Create: `tests/evaluation/test_attorney_v21_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: Tasks 1-4 request, compiler, rubric, artifact, manifest, and state APIs.
- Produces: `AttorneyEvaluatorV21`, `GuardedSubmissionResultV21`, `initialize_evaluation_v21`, `resume_evaluation_v21`, `next_evaluator_request_v21`, `preflight_evaluator_response_v21`, `guarded_submit_evaluator_response_v21`, `submit_evaluator_response_v21`, `stop_evaluation_v21_inconclusive`, and `run_evaluation_v21`.

- [ ] **Step 1: Write the state-machine RED tests**

Cover no-dispute flow, three mixed referee decisions, substantive unresolved continuing to grade, two grader lanes, ordinary batch advancement, contested advancement, stable PASS/FAIL, outcome-changing INCONCLUSIVE, mechanical repair, second mechanical stop, interruption/resume, and no repeated accepted fragment.

```python
def test_unresolved_referee_continues_to_contested_grading(tmp_path: Path) -> None:
    run = initialize_case_with_one_dispute(tmp_path)
    submit_referee(run, decision="unresolved", reason="SOURCE_AMBIGUITY")
    request = next_evaluator_request_v21(run)
    assert request is not None
    assert request.operation == "grade_report"
    assert request.safe_metadata["fragment_kind"] == "contested_requirement"


def test_second_fragment_refusal_stops_mechanically(tmp_path: Path) -> None:
    run = pending_referee_fragment(tmp_path)
    assert not guarded_submit_evaluator_response_v21(run, invalid_payload()).accepted
    assert not guarded_submit_evaluator_response_v21(run, invalid_payload()).accepted
    state = stop_evaluation_v21_inconclusive(run, "MECHANICAL_RESPONSE_INVALID")
    assert state.terminal_reason == "INCONCLUSIVE_MECHANICAL"
```

- [ ] **Step 2: Run workflow tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v21_workflow.py -q
```

- [ ] **Step 3: Implement deterministic call ordering**

Use call IDs that identify stage without relying on filenames supplied by a role:

```text
source-review
source-audit
source-referee-D0001
source-referee-D0002
grade-A-lane1-batch0001
grade-A-lane1-contested-CREQ-0001
grade-A-lane2-batch0001
grade-A-lane2-contested-CREQ-0001
```

For comparator cases, complete both lanes for A before B using the same deterministic grammar.

- [ ] **Step 4: Implement guarded submission and advancement**

```python
def guarded_submit_evaluator_response_v21(
    run_dir: Path,
    response: object,
) -> GuardedSubmissionResultV21:
    preflight = preflight_evaluator_response_v21(run_dir, response)
    if not preflight.valid:
        return GuardedSubmissionResultV21(accepted=False, preflight=preflight, state=None)
    return GuardedSubmissionResultV21(
        accepted=True,
        preflight=preflight,
        state=submit_evaluator_response_v21(run_dir, response),
    )
```

Accepted referee fragments advance to the next dispute or compile the baseline. Accepted grade fragments advance to the next deterministic batch/item or seal the lane aggregate. Never reconstruct progress from directory listing alone.

- [ ] **Step 5: Implement mechanical stop and substantive terminals**

Mechanical stop stores only the safe code and pending fragment metadata. Substantive unresolved continues. Outcome sensitivity is evaluated only after complete lane aggregates. Valid FAIL and substantive INCONCLUSIVE are terminal and never retried.

- [ ] **Step 6: Run workflow, neighboring evaluator, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_workflow.py \
  tests/evaluation/test_attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v2_workflow.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_v21_workflow.py \
  tests/evaluation/test_attorney_v21_workflow.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation
```

- [ ] **Step 7: Commit the full-runtime workflow**

```bash
git add src/regulatory_harvest/evaluation/attorney_v21_workflow.py \
  src/regulatory_harvest/evaluation/__init__.py \
  tests/evaluation/test_attorney_v21_workflow.py
git diff --cached --check
git commit -m "feat: run fragmented evaluator protocol 2.1"
```

### Task 6: Full CLI Routing and Retained-Protocol Boundaries

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `scripts/attorney_eval_full.py`
- Modify: `scripts/harvest_skill.py`
- Modify: `tests/cli/test_eval_cli.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_evaluation_capsule_provenance.py`

**Interfaces:**
- Consumes: Task 4 protocol detector and Task 5 public workflow APIs.
- Produces: default Protocol 2.1 `eval-init`, protocol-aware status/next/preflight/submit-safe/stop/verify routing, and replay-only Protocol 1.3/2.0 behavior.

- [ ] **Step 1: Write routing and compatibility RED tests**

Assert new initialization emits `schema_version: "2.1"`; 2.1 commands route to the new workflow; valid 2.0 and 1.3 status/verify remain byte-preserving; every mutation command against 1.3 or 2.0 returns `EVALUATION_LEGACY_READ_ONLY`; unknown versions return `EVALUATION_PROTOCOL_UNSUPPORTED`; malformed initialization is write-free.

```python
def test_eval_init_defaults_to_protocol_21(tmp_path: Path) -> None:
    result = run_full("eval-init", case=case_path(), run=tmp_path / "run")
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema_version"] == "2.1"
```

- [ ] **Step 2: Run focused CLI tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/cli/test_eval_cli.py \
  tests/scripts/test_harvest_skill.py \
  tests/scripts/test_evaluation_capsule_provenance.py \
  -q -k 'protocol_21 or retained_protocol or eval_init_defaults'
```

- [ ] **Step 3: Add explicit Protocol 2.1 routing**

Route by detected manifest version. Initialization calls only `initialize_evaluation_v21`. Protocol 2.0 remains status/verify only and uses its unchanged verifier/result semantics. Preserve stable exit codes and public-safe diagnostics.

```python
protocol = detect_evaluation_protocol(run)
if protocol == "2.1":
    return _run_v21_command(args, run)
if protocol == "2.0":
    return _run_v20_read_only_command(args, run)
if protocol == "1.3":
    return _run_v13_read_only_command(args, run)
raise EvaluationIntegrityError("EVALUATION_PROTOCOL_UNSUPPORTED")
```

- [ ] **Step 4: Add a strict scripted Protocol 2.1 adapter**

The scripted fixture adapter must compare the exact current request fingerprint and operation before returning its payload. It must record `scripted_fixture`, never `fresh_context`, and must not loosen production validation.

- [ ] **Step 5: Run full CLI/harness and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/cli/test_eval_cli.py \
  tests/scripts/test_harvest_skill.py \
  tests/scripts/test_evaluation_capsule_provenance.py -q
../../.venv/bin/ruff check \
  src/regulatory_harvest/evaluation/attorney_cli.py \
  scripts/attorney_eval_full.py \
  scripts/harvest_skill.py \
  tests/cli/test_eval_cli.py \
  tests/scripts/test_harvest_skill.py \
  tests/scripts/test_evaluation_capsule_provenance.py
PYTHONPATH=src ../../.venv/bin/mypy src scripts/attorney_eval_full.py scripts/harvest_skill.py
```

- [ ] **Step 6: Commit full CLI routing**

```bash
git add src/regulatory_harvest/evaluation/attorney_cli.py \
  scripts/attorney_eval_full.py scripts/harvest_skill.py \
  tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py \
  tests/scripts/test_evaluation_capsule_provenance.py
git diff --cached --check
git commit -m "feat: route new evaluations through protocol 2.1"
```

### Task 7: Standard-Library Portable Mirror and Differential Parity

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: exact full-runtime Protocol 2.1 request, response, manifest, transition, diagnostic, and artifact bytes from Tasks 1-6.
- Produces: isolated `python3 -I -S` Protocol 2.1 behavior with exact full/portable parity and retained 1.3/2.0 replay.

- [ ] **Step 1: Add table-driven differential RED tests**

Include at least these exact paths: no dispute; mixed referee outcomes; outcome-stable PASS; outcome-stable FAIL; outcome-changing INCONCLUSIVE; referee repair; grade repair; mechanical terminal; partial referee resume; partial grade resume; retained 2.0 replay; retained 1.3 replay; unknown protocol; swapped fragment; tampered aggregate; symlink/path refusal.

Every row must compare command name, exit code, stdout, stderr, and the complete artifact tree.

- [ ] **Step 2: Run the differential selection and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_harvest_skill.py -q \
  -k 'protocol_21_portable_parity'
```

- [ ] **Step 3: Implement the bounded portable mirror**

Add a clearly marked `# Protocol 2.1 portable mirror` section. Reproduce strict models with bounded dict/list validators, canonical JSON, exact fingerprints, deterministic batch/dispute inventories, transition grammar, and verifier rules using only the standard library. Do not import Pydantic or package modules.

```python
# Protocol 2.1 portable mirror
_V21_PROTOCOL = "2.1"
_V21_MAX_GRADE_BATCH = 5
_V21_UNRESOLVED_REASONS = frozenset(
    {
        "SOURCE_AMBIGUITY",
        "SOURCE_CONFLICT",
        "SOURCE_GAP",
        "BOTH_POSITIONS_UNSUPPORTED",
    }
)
```

- [ ] **Step 4: Add protocol-aware portable dispatcher branches**

`harvest_portable.py` must initialize 2.1, route existing 2.1 runs to the portable mirror, and route 1.3/2.0 only to their replay/status/verify paths. Terminal exit calculation must load the protocol-matching verified result.

- [ ] **Step 5: Run portable, differential, and isolated gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_harvest_skill.py -q \
  -k 'protocol_21 or retained_protocol'
python3 -I -S scripts/harvest_portable.py eval-init --help
python3 -I -S scripts/harvest_portable.py eval-verify --help
../../.venv/bin/ruff check scripts/attorney_eval_portable.py \
  scripts/harvest_portable.py tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py
PYTHONPATH=src ../../.venv/bin/mypy src
```

- [ ] **Step 6: Measure the portable delta**

Record full-runtime Protocol 2.1 module lines and the marker-derived portable 2.1 section lines in the Task 7 report. Do not adopt an arbitrary line target; flag accidental duplication and helpers that can be generated from canonical schemas without weakening isolated execution.

- [ ] **Step 7: Commit portable parity**

```bash
git add scripts/attorney_eval_portable.py scripts/harvest_portable.py \
  tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py
git diff --cached --check
git commit -m "feat: mirror evaluator protocol 2.1 portably"
```

### Task 8: Packaging, Templates, Operator Documentation, and Compatibility Fixtures

**Files:**
- Create: `assets/attorney-evaluation-v21-response.template.json`
- Create: `tests/fixtures/attorney-eval-v21/` fixture tree
- Modify: `scripts/skill-package-files.txt`
- Modify: `scripts/build_skill.py`
- Modify: `README.md`
- Modify: `SKILL.md`
- Modify: `docs/evaluation.md`
- Modify: `references/attorney-evaluation.md`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/skill/test_skill_package.py`
- Modify: `tests/cli/test_eval_cli.py`

**Interfaces:**
- Consumes: stable public CLI and portable behavior from Tasks 6-7.
- Produces: packaged Protocol 2.1 runtime, canonical compatibility template, documented operator contract, retained fixtures, and a complete fictional end-to-end lifecycle.

- [ ] **Step 1: Write package and documentation RED tests**

Require all seven new full-runtime modules and the new template exactly once in the sorted manifest. Require docs to call 2.1 the new-run default only after the gate, describe fragmented referee/grade behavior, distinguish substantive unresolved from mechanical failure, and label 1.3/2.0 replay-only.

- [ ] **Step 2: Run package/document tests and confirm RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/scripts/test_build_skill.py \
  tests/skill/test_skill_package.py -q -k 'protocol_21 or evaluator_response_template'
```

- [ ] **Step 3: Add canonical package entries and response template**

The template contains the seven controller-owned envelope keys, protocol `2.1`, an empty object payload, sorted compact JSON, and no trailing newline. Preserve the Protocol 1.3 and 2.0 templates byte-for-byte.

```json
{"judge_isolation":"fresh_context","model_name":"example-model","operation":"source_referee","payload":{},"provider_name":"example-provider","request_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","schema_version":"2.1"}
```

- [ ] **Step 4: Write operator and public documentation**

Document one initial response plus one fresh repair per fragment, source-only referee packets, bounded grade batches, contested requirements, outcome sensitivity, replay compatibility, and the limited meaning of PASS/FAIL/INCONCLUSIVE. Keep commands attorney-hidden in normal delivery.

- [ ] **Step 5: Build a fictional deterministic 2.1 fixture**

The fixture must execute source review, nonempty audit, at least three referee fragments with mixed decisions including one substantive unresolved, two grader lanes, ordinary batches, contested grading, sensitivity calculation, terminal status, and replay. Include a second case where the unresolved dispute changes the outcome.

- [ ] **Step 6: Run package, fixture, and docs gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/scripts/test_build_skill.py \
  tests/skill/test_skill_package.py \
  tests/cli/test_eval_cli.py -q
../../.venv/bin/ruff check scripts/build_skill.py \
  tests/scripts/test_build_skill.py tests/skill/test_skill_package.py \
  tests/cli/test_eval_cli.py
PYTHONPATH=src ../../.venv/bin/mypy src
```

- [ ] **Step 7: Commit package and documentation**

```bash
git add assets/attorney-evaluation-v21-response.template.json \
  tests/fixtures/attorney-eval-v21 scripts/skill-package-files.txt \
  scripts/build_skill.py README.md SKILL.md docs/evaluation.md \
  references/attorney-evaluation.md tests/scripts/test_build_skill.py \
  tests/skill/test_skill_package.py tests/cli/test_eval_cli.py
git diff --cached --check
git commit -m "docs: package evaluator protocol 2.1"
```

### Task 9: Public Release Gate and Independent Review

**Files:**
- Modify only if a failing gate exposes a traced defect in a previously owned file.
- Create ignored evidence report `.superpowers/sdd/2026-08-18-evaluator-protocol-2-1/task-9-report.md`.

**Interfaces:**
- Consumes: completed Tasks 1-8.
- Produces: exact public verification evidence and an independent readiness decision for one separately authorized private run.

- [ ] **Step 1: Run the complete focused Protocol 2.1 matrix**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_v21_models.py \
  tests/evaluation/test_attorney_v21_compiler.py \
  tests/evaluation/test_attorney_v21_requests.py \
  tests/evaluation/test_attorney_v21_rubric.py \
  tests/evaluation/test_attorney_v21_artifacts.py \
  tests/evaluation/test_attorney_v21_workflow.py \
  tests/cli/test_eval_cli.py \
  tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py \
  tests/scripts/test_build_skill.py \
  tests/skill/test_skill_package.py -q
```

- [ ] **Step 2: Run the complete repository gates once**

```bash
PYTHONPATH=src ../../.venv/bin/pytest -q
../../.venv/bin/ruff check .
PYTHONPATH=src ../../.venv/bin/mypy src
git diff --check
```

Capture exact totals and warning text. Do not report a pass from a detached process whose terminal result was not observed.

- [ ] **Step 3: Build twice from two detached exact-commit clones**

Use `git clone --no-local`, build the package in each clean clone, and require identical ZIP bytes, sorted unique member lists, exact Git-blob/member equality, clean extraction, and full plus `python3 -I -S` help.

- [ ] **Step 4: Run release and privacy audits**

Run repository and both archive audits with the approved sealed owner-marker file. Require zero automated findings. Preserve the manual owner/publication authorization boundary.

- [ ] **Step 5: Perform adversarial review**

Review at minimum: raw/model-constructed/cyclic/oversized responses, fragment swaps, cross-case replay, cross-dispute replay, cross-lane replay, partial histories, terminal orphan requests, result-shaped junk, symlink/FIFO inventory, write rollback, source/report quote ambiguity, protocol downgrade, and retained 1.3/2.0 replay.

- [ ] **Step 6: Obtain independent spec and code review**

The reviewer must report Critical/Important/Minor findings, spec PASS/FAIL, code-quality PASS/FAIL, and Ready yes/no. Resolve every Important or Critical finding with a new test-first correction and rerun affected plus full gates.

- [ ] **Step 7: Record the public gate**

Write exact commit, package hash, test totals, static results, audit results, compatibility results, line measurements, review findings, and explicit private-run authorization status to the ignored Task 9 report. Do not include private paths, markers, sources, reports, or evaluation artifacts.

### Task 10: Separately Authorized Private Readiness Gate

**Files:**
- No tracked repository files.
- Private artifacts only under the approved local evaluation root.
- Public-safe ignored receipt `.superpowers/sdd/2026-08-18-evaluator-protocol-2-1/task-10-private-readiness-receipt.json`.

**Interfaces:**
- Consumes: exact reviewed commit/package from Task 9 and separate explicit owner authorization.
- Produces: one verified terminal private readiness result; never a publication action.

- [ ] **Step 1: Stop for explicit authorization**

Do not begin Task 10 merely because Task 9 is green. Obtain the owner's explicit approval for one private cycle against the exact reviewed commit and archive hash.

- [ ] **Step 2: Bind privacy, package, install, and prior-cycle immutability**

Run vault bootup/offline guard, two-build re-verification, sealed owner-marker audit, recoverable install, and prior-cycle tree hash before creating the one new cycle.

- [ ] **Step 3: Run one fresh source-only qualification**

Use the exact source bytes and build binding. Permit only the approved qualification repair bound. Require terminal `ADMITTED` and full/isolated replay equality.

- [ ] **Step 4: Generate exactly one candidate**

Use one fresh isolated generation context and the exact captured build. Require completed deterministic evidence precision, proposition coverage, and provision recall, then full/isolated capsule verification.

- [ ] **Step 5: Run exactly one Protocol 2.1 evaluation**

Use fresh contexts as declared by the protocol, one initial plus one fresh repair per fragment, no replacement candidate, no alternate case, no repeated cycle, and no rejected-content reuse.

- [ ] **Step 6: Verify and report the terminal result**

Run full and isolated status/verify, prove exact prior-cycle immutability, record accepted/refused/repair counts, and distinguish substantive PASS/FAIL/INCONCLUSIVE from `INCONCLUSIVE_MECHANICAL`.

A substantive FAIL is a completed result and is not retried. A mechanical terminal does not establish readiness. No publication, visibility, tag, release, performance claim, or default-protocol change is authorized without a separate owner decision.

## Execution Order and Review Boundaries

Tasks 1-8 are sequential because their interfaces and shared integration files are dependent. Do not run implementation agents concurrently against the same worktree.

Each task must receive:

1. test-first RED evidence;
2. focused GREEN evidence;
3. static checks for its changed files;
4. a scoped commit containing only owned files; and
5. an independent review before the next dependent task consumes its interface.

Task 9 is the complete public gate. Task 10 is not an automatic continuation; it is a separately authorized private operation.

## Specification Coverage Matrix

| Specification requirement | Implementing task(s) |
|---|---|
| One dispute per referee request and no role-authored engine IDs | Tasks 1-2 |
| Substantive unresolved reason and evidence contract | Tasks 1-2 |
| Common baseline plus both contested alternatives | Task 2 |
| Ordinary batches of at most five | Tasks 1 and 3 |
| Individual contested grading by two lanes | Tasks 1 and 3 |
| Deterministic fragment coverage and lane aggregation | Tasks 3-5 |
| Outcome-stable PASS/FAIL and outcome-changing INCONCLUSIVE | Tasks 3 and 5 |
| Mechanical versus substantive terminal separation | Tasks 1, 4, and 5 |
| Exact pending-fragment resume without repeated judgments | Tasks 4-5 |
| Protocol 1.3 and 2.0 replay-only compatibility | Tasks 4, 6, and 7 |
| Full and isolated portable parity | Task 7 |
| Packaging and operator contract | Task 8 |
| Complete public verification and independent review | Task 9 |
| Single separately authorized private readiness cycle | Task 10 |
