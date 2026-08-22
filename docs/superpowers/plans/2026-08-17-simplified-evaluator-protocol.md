# Simplified Evaluator Protocol 2.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace LLM-authored canonical ledgers and repair transactions with semantic evaluator responses compiled and sealed by deterministic protocol 2.0 code, while preserving exact protocol 1.3 replay.

**Architecture:** Add a parallel protocol 2.0 model, compiler, request, rubric, artifact, and workflow surface. New CLI evaluations use 2.0; retained 1.3 runs dispatch to the frozen verifier only. The full runtime is implemented first, then mirrored compactly in the stdlib-only portable runner and proven byte-equivalent.

**Tech Stack:** Python 3.11+, Pydantic 2.8+, pytest, Ruff, mypy strict, stdlib-only portable Python, canonical JSON and SHA-256 storage helpers.

**Spec:** `docs/superpowers/specs/2026-08-17-simplified-evaluator-protocol-design.md`

## Global Constraints

- Protocol `2.0` is the only protocol initialized for new evaluations after the readiness gate passes.
- Protocol `1.3` artifacts remain immutable and byte-exactly replay-verifiable; they are never migrated, resumed through 2.0, or reinterpreted.
- No LLM role originates canonical IDs, ordering, fingerprints, hashes, aggregate scores, repair transactions, or storage artifacts.
- A grader may only echo an engine-supplied requirement ID.
- Each LLM call permits one initial response and at most one fresh-context mechanical repair.
- Valid substantive `FAIL` and `INCONCLUSIVE` responses are never retried.
- Two graders evaluate each report; any material grader disagreement yields `INCONCLUSIVE` with no grading-referee call.
- One or two blinded reports are supported; each is graded independently against the same baseline, and comparison never forces a winner from an inconclusive result.
- Exact-source verification, report-passage resolution, provenance, privacy, path containment, write-free refusal, atomic commit, replay, and tamper detection remain fail-closed.
- Full and portable runtimes must emit equivalent canonical bytes, diagnostics, state transitions, and replay results.
- Python remains `>=3.11`; add no runtime dependency.
- Do not publish, install, push, create a release, or run a private evaluation without the separately authorized release-qualification step.

---

### Task 1: Freeze the 1.3 baseline and define strict 2.0 contracts

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_models.py`
- Create: `tests/evaluation/test_attorney_v2_models.py`
- Create: `docs/verification/evaluator-2.0-baseline.md`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: `StrictModel`, `canonical_json_bytes`, and existing case/source/candidate models from `attorney_models.py`.
- Produces: `EvaluatorOperationV2`, `EvaluationPhaseV2`, `EvaluationTerminalStatusV2`, `AbsoluteDispositionV2`, `ComparisonDispositionV2`, `RequirementKindV2`, `ImportanceV2`, `SemanticPassage`, `SemanticDependency`, `SemanticProposal`, `SourceReviewV2`, `IndexedProposalV2`, `AuditConcernV2`, `SourceAuditV2`, `MaterialDisputeV2`, `SourceRefereeDecisionV2`, `SourceRefereeResponseV2`, `ResolvedPassageV2`, `CanonicalRequirementV2`, `CanonicalBaselineV2`, `RequirementGradeV2`, `UnsupportedAssertionV2`, `GradeResponseV2`, `ReconciledGradeV2`, `RubricV2`, `ReportResultV2`, `ComparisonResultV2`, `EvaluationResultV2`, `EvaluationCallRecordV2`, `EvaluatorRequestV2`, `EvaluatorResponseV2`, `EvaluationManifestV2`, `EvaluationRunStateV2`, and `CompletedEvaluationV2`.

- [ ] **Step 1: Record the protocol 1.3 comparison baseline**

Run:

```bash
git rev-parse HEAD
wc -l \
  src/regulatory_harvest/evaluation/attorney_models.py \
  src/regulatory_harvest/evaluation/attorney_workflow.py \
  src/regulatory_harvest/evaluation/attorney_ledger.py \
  src/regulatory_harvest/evaluation/attorney_artifacts.py \
  src/regulatory_harvest/evaluation/attorney_grading.py \
  src/regulatory_harvest/evaluation/attorney_scoring.py \
  scripts/attorney_eval_portable.py
```

Record commit `83e27583159273480927ec35e82dd5e159d39b8f`, core full-plus-portable size `21,148` lines, six 1.3 evaluator operation types, two allowed repair responses, one grading-referee loop, and the LLM-authored mechanical fields named in the spec. Set these 2.0 targets in the document:

```markdown
- Four substantive operation types: source_review, source_audit, source_referee, grade_report.
- One mechanical repair response maximum per call.
- Zero grading-referee operations.
- Zero LLM-originated canonical IDs, order fields, fingerprints, hashes, scores, or transactions.
- Protocol 2.0 full-plus-portable implementation no larger than 12,689 lines, 60% of the 1.3 core surface.
- Every inner LLM response model has at most eight top-level fields.
```

- [ ] **Step 2: Write strict-model RED tests**

Add tests that instantiate the exact semantic shapes and reject coercion, extra fields, blank text, duplicate passages, reviewer-authored IDs, and unsupported operations:

```python
def test_source_review_accepts_semantics_without_canonical_fields() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                {
                    "statement": "A covered operator must file the notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The operative text states a mandatory filing duty.",
                }
            ],
        }
    )
    assert review.proposals[0].kind is RequirementKindV2.OBLIGATION
    assert "requirement_id" not in review.model_dump(mode="json")["proposals"][0]


@pytest.mark.parametrize(
    "forbidden",
    ["requirement_id", "walk_order", "fingerprint", "score", "repair_transactions"],
)
def test_semantic_proposal_rejects_canonical_fields(forbidden: str) -> None:
    payload = valid_semantic_proposal_payload()
    payload[forbidden] = "forbidden"
    with pytest.raises(ValidationError):
        SemanticProposal.model_validate(payload)
```

- [ ] **Step 3: Run the model tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_models.py -q`

Expected: collection fails because `attorney_v2_models` does not exist.

- [ ] **Step 4: Implement the strict contracts**

Use closed enums and `StrictModel` with exact fields. The core semantic models must have these signatures:

```python
PROTOCOL_V2: Literal["2.0"] = "2.0"


class EvaluatorOperationV2(StrEnum):
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE = "source_referee"
    GRADE_REPORT = "grade_report"


class EvaluationTerminalStatusV2(StrEnum):
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"


class RequirementKindV2(StrEnum):
    OBLIGATION = "obligation"
    PROHIBITION = "prohibition"
    PERMISSION = "permission"
    EXCEPTION = "exception"
    DEFINITION = "definition"
    DEADLINE = "deadline"
    ENFORCEMENT = "enforcement"
    GAP = "gap"


class ImportanceV2(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class SemanticPassage(StrictModel):
    source_id: str
    quote: str


class SemanticDependency(StrictModel):
    relationship: Literal["depends_on", "exception_to", "defines", "enforced_by"]
    target_statement: str


class SemanticProposal(StrictModel):
    statement: str
    kind: RequirementKindV2
    importance: ImportanceV2
    passages: list[SemanticPassage] = Field(min_length=1)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    rationale: str


class SourceReviewV2(StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    proposals: list[SemanticProposal]
```

Use these exact inner response boundaries:

```python
class AuditConcernV2(StrictModel):
    target_proposal_ref: str | None = Field(pattern=r"^P[0-9]{4}$")
    concern_type: Literal[
        "omission",
        "incorrect_statement",
        "incorrect_evidence",
        "incorrect_relationship",
        "ambiguity",
    ]
    passages: list[SemanticPassage] = Field(min_length=1)
    explanation: str
    correction: SemanticProposal | None = None


class SourceAuditV2(StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    concerns: list[AuditConcernV2]


class SourceRefereeDecisionV2(StrictModel):
    dispute_id: str = Field(pattern=r"^D[0-9]{4}$")
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    passages: list[SemanticPassage] = Field(min_length=1)
    rationale: str


class SourceRefereeResponseV2(StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    decisions: list[SourceRefereeDecisionV2]


class RequirementGradeV2(StrictModel):
    requirement_id: str = Field(pattern=r"^REQ-[0-9]{4}$")
    disposition: Literal["met", "partially_met", "not_met", "uncertain"]
    report_passages: list[str]
    rationale: str
    omission: str | None = None


class UnsupportedAssertionV2(StrictModel):
    report_passage: str
    importance: ImportanceV2
    rationale: str


class GradeResponseV2(StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    anonymous_label: Literal["A", "B"]
    baseline_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    requirement_grades: list[RequirementGradeV2]
    unsupported_assertions: list[UnsupportedAssertionV2]
    baseline_defect: str | None = None
```

Model validators enforce that an omission has no target and includes a
correction; an incorrect statement, evidence choice, or relationship has one
known target and includes a correction; ambiguity has one known target and may
omit correction. Referee decisions cover every engine-issued dispute exactly
once. Grade responses cover every engine-issued requirement exactly once.

Use these exact rubric and run-manifest fields:

```python
class RubricV2(StrictModel):
    version: Literal["attorney-eval-v2"]
    importance_weights: dict[ImportanceV2, int]
    critical_recall_floor: float
    weighted_coverage_floor: float
    material_unsupported_assertions_allowed: Literal[0]


class EvaluationCallRecordV2(StrictModel):
    call_id: str
    operation: EvaluatorOperationV2
    anonymous_label: Literal["A", "B"] | None = None
    state: Literal["pending", "accepted"]
    request_artifact_path: str
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_artifact_path: str | None = None
    response_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    provider_name: str | None = None
    model_name: str | None = None
    judge_isolation: Literal["fresh_context", "scripted_fixture"] | None = None


class EvaluationManifestV2(StrictModel):
    protocol_version: Literal["2.0"] = PROTOCOL_V2
    case_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_envelope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    build_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    rubric_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: Literal["semantic-compiler-v2"]
    baseline_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    phase: EvaluationPhaseV2
    terminal_status: EvaluationTerminalStatusV2 | None = None
    calls: list[EvaluationCallRecordV2]
    artifacts: list[ArtifactRecord]
    manifest_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
```

`EvaluationCallRecordV2` records only accepted role responses plus the single
pending request; refused-response bytes and details never enter the run.

Define audit corrections with the same `SemanticProposal`, engine-issued request-local references matching `^P[0-9]{4}$`, referee dispute references matching `^D[0-9]{4}$`, and grader requirement references matching `^REQ-[0-9]{4}$`. Requests have exactly `schema_version`, `operation`, `request_fingerprint`, `system_instructions`, `json_schema`, `payload`, and `safe_metadata`. Responses have exactly `schema_version`, `operation`, `request_fingerprint`, `provider_name`, `model_name`, `judge_isolation`, and `payload`. Use the existing request-fingerprint convention.

- [ ] **Step 5: Export only the public 2.0 value types**

Add the stable value types to `evaluation/__init__.py`; do not export workflow mutation helpers yet:

```python
from .attorney_v2_models import (
    CanonicalBaselineV2,
    EvaluationResultV2,
    GradeResponseV2,
    SourceAuditV2,
    SourceReviewV2,
)
```

- [ ] **Step 6: Run focused and legacy model tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_models.py tests/evaluation/test_attorney_models.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v2_models.py tests/evaluation/test_attorney_v2_models.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v2_models.py
```

Expected: all pass; existing 1.3 model bytes remain unchanged.

- [ ] **Step 7: Commit**

```bash
git add docs/verification/evaluator-2.0-baseline.md \
  src/regulatory_harvest/evaluation/attorney_v2_models.py \
  src/regulatory_harvest/evaluation/__init__.py \
  tests/evaluation/test_attorney_v2_models.py
git commit -m "feat: define simplified evaluator contracts"
```

---

### Task 2: Compile semantic proposals into a canonical baseline

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_compiler.py`
- Create: `tests/evaluation/test_attorney_v2_compiler.py`

**Interfaces:**
- Consumes: `CaseEnvelope`, `SourceReviewV2`, `SourceAuditV2`, and `SourceRefereeResponseV2`.
- Produces: `CompilationError`, `index_review(review: SourceReviewV2) -> tuple[IndexedProposalV2, ...]`, `material_disputes(review, audit) -> tuple[MaterialDisputeV2, ...]`, `resolve_exact_passage(source_text: str, passage: SemanticPassage) -> ResolvedPassageV2`, and `compile_baseline(envelope, review, audit, referee) -> CanonicalBaselineV2`.

- [ ] **Step 1: Write compiler RED tests**

Cover deterministic IDs and ordering, exact quote resolution, duplicate quote ambiguity, auditor omission correction, accepted reviewer/auditor decisions, unresolved disputes, exact dependency matching, shuffled proposal order, malformed validation-bypass inputs, and no mutation:

```python
def test_compiler_assigns_ids_after_semantic_decisions() -> None:
    baseline = compile_baseline(envelope(), review_with_exception(), empty_audit(), None)
    assert [item.requirement_id for item in baseline.requirements] == [
        "REQ-0001",
        "REQ-0002",
    ]
    assert baseline.relationships[0].source_requirement_id == "REQ-0002"
    assert baseline.relationships[0].target_requirement_id == "REQ-0001"


def test_compiler_rejects_nonunique_exact_quote() -> None:
    with pytest.raises(CompilationError, match="PASSAGE_AMBIGUOUS"):
        resolve_exact_passage("notice notice", SemanticPassage(source_id="s", quote="notice"))
```

- [ ] **Step 2: Run the compiler tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_compiler.py -q`

Expected: collection fails because the compiler module does not exist.

- [ ] **Step 3: Implement passage resolution and request-local indexing**

Use a unique exact substring match; never ask the LLM for offsets:

```python
def resolve_exact_passage(source_text: str, passage: SemanticPassage) -> ResolvedPassageV2:
    starts = tuple(_all_occurrences(source_text, passage.quote))
    if not starts:
        raise CompilationError("PASSAGE_NOT_FOUND")
    if len(starts) != 1:
        raise CompilationError("PASSAGE_AMBIGUOUS")
    start = starts[0]
    return ResolvedPassageV2(
        source_id=passage.source_id,
        start_char=start,
        end_char=start + len(passage.quote),
        quote=passage.quote,
    )


def index_review(review: SourceReviewV2) -> tuple[IndexedProposalV2, ...]:
    return tuple(
        IndexedProposalV2(proposal_ref=f"P{index:04d}", proposal=proposal)
        for index, proposal in enumerate(review.proposals, start=1)
    )
```

- [ ] **Step 4: Implement dispute construction and canonical compilation**

Treat every returned audit concern as material by contract. A nonempty audit
therefore creates one fresh-referee request. Apply only explicit referee
choices. Reject exact duplicate accepted proposals. Sort accepted proposals by
resolved first passage `(source_id, start_char, end_char)`, then kind,
normalized statement, and the SHA-256 of the complete canonical resolved
proposal as a final order-independent tiebreaker; assign `REQ-0001` onward and
`REL-0001` onward. Resolve a dependency only when `target_statement` exactly
normalizes to one accepted proposal statement; zero or multiple targets are
compilation errors. Compute the baseline fingerprint from canonical bytes with
the fingerprint field omitted.

```python
def compile_baseline(
    envelope: CaseEnvelope,
    review: SourceReviewV2,
    audit: SourceAuditV2,
    referee: SourceRefereeResponseV2 | None,
) -> CanonicalBaselineV2:
    accepted = _apply_referee_choices(index_review(review), audit, referee)
    resolved = [_resolve_proposal(envelope, item) for item in accepted]
    ordered = sorted(resolved, key=_canonical_requirement_sort_key)
    requirements = _assign_requirement_ids(ordered)
    relationships = _compile_relationships(requirements)
    return _seal_baseline(envelope.case_fingerprint, requirements, relationships)
```

- [ ] **Step 5: Run focused and adversarial compiler tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_compiler.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v2_compiler.py tests/evaluation/test_attorney_v2_compiler.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v2_compiler.py
```

Expected: all tests pass; one root compilation defect produces one bounded diagnostic rather than reference-scaled issues.

- [ ] **Step 6: Commit**

```bash
git add src/regulatory_harvest/evaluation/attorney_v2_compiler.py \
  tests/evaluation/test_attorney_v2_compiler.py
git commit -m "feat: compile semantic evaluation baselines"
```

---

### Task 3: Build narrow source-review, audit, referee, and grade requests

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_requests.py`
- Create: `tests/evaluation/test_attorney_v2_requests.py`

**Interfaces:**
- Consumes: frozen `CaseEnvelope`, indexed proposals, material disputes, `CanonicalBaselineV2`, anonymous report text, and `RubricV2`.
- Produces: `build_source_review_request`, `build_source_audit_request`, `build_source_referee_request`, `build_grade_request`, and `mechanical_retry_request`, each returning `EvaluatorRequestV2`.

- [ ] **Step 1: Write request-byte RED tests**

Assert exact operation, payload, schema, source-only boundaries, blinded labels, and forbidden mechanical instructions:

```python
def test_source_review_request_contains_sources_but_no_candidate() -> None:
    request = build_source_review_request(envelope())
    encoded = canonical_json_bytes(request.model_dump(mode="json"))
    assert request.operation is EvaluatorOperationV2.SOURCE_REVIEW
    assert b"candidate" not in encoded
    assert b"walk_order" not in encoded
    assert b"repair_transaction" not in encoded


def test_grade_request_supplies_ids_without_asking_grader_to_create_them() -> None:
    request = build_grade_request(envelope(), baseline(), "A", RUBRIC_V2)
    assert request.payload["requirements"][0]["requirement_id"] == "REQ-0001"
    assert "assign" not in request.system_instructions.lower()
```

- [ ] **Step 2: Run request tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_requests.py -q`

Expected: collection fails because the request module does not exist.

- [ ] **Step 3: Implement the four request builders**

Each request must use one strict inner response schema and instructions limited to substantive work:

```python
def build_source_review_request(envelope: CaseEnvelope) -> EvaluatorRequestV2: ...

def build_source_audit_request(
    envelope: CaseEnvelope,
    indexed: tuple[IndexedProposalV2, ...],
) -> EvaluatorRequestV2: ...

def build_source_referee_request(
    envelope: CaseEnvelope,
    disputes: tuple[MaterialDisputeV2, ...],
) -> EvaluatorRequestV2: ...

def build_grade_request(
    envelope: CaseEnvelope,
    baseline: CanonicalBaselineV2,
    label: Literal["A", "B"],
    rubric: RubricV2,
) -> EvaluatorRequestV2: ...
```

The auditor instructions say to return only material concerns. The referee receives all material disputes in one bounded call. The grader receives one anonymous report, the complete baseline, and no other report or identity metadata.

- [ ] **Step 4: Implement retry identity without response feedback**

```python
def mechanical_retry_request(request: EvaluatorRequestV2) -> EvaluatorRequestV2:
    return EvaluatorRequestV2.model_validate(request.model_dump(mode="json"))
```

The rejected response and field-specific validator details are not added to the
packet or run. The active controller enforces the one-repair bound.

- [ ] **Step 5: Run request, privacy, and byte-stability tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_requests.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v2_requests.py tests/evaluation/test_attorney_v2_requests.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v2_requests.py
```

- [ ] **Step 6: Commit**

```bash
git add src/regulatory_harvest/evaluation/attorney_v2_requests.py \
  tests/evaluation/test_attorney_v2_requests.py
git commit -m "feat: add semantic evaluator requests"
```

---

### Task 4: Reconcile two graders and apply the versioned rubric

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_rubric.py`
- Create: `tests/evaluation/test_attorney_v2_rubric.py`

**Interfaces:**
- Consumes: `CanonicalBaselineV2`, two `GradeResponseV2` values, candidate report text, and `RubricV2`.
- Produces: `validate_grade_response`, `reconcile_grades`, `score_report`, and `compare_report_results`.

- [ ] **Step 1: Write rubric RED tests**

Cover complete requirement cardinality, exact report passages, unknown and duplicate requirement IDs, agreement, disagreement, critical omission, weighted coverage, material unsupported assertions, baseline-defect flags, single-report results, and paired comparison:

```python
def test_material_grade_disagreement_is_inconclusive() -> None:
    result = reconcile_grades(baseline(), grade("met"), grade("partially_met"), report())
    assert result.disposition is AbsoluteDispositionV2.INCONCLUSIVE
    assert result.reason_codes == ["GRADER_DISAGREEMENT"]


def test_valid_fail_is_scored_without_a_retry_signal() -> None:
    result = score_report(baseline(), agreed_grade("not_met"), RUBRIC_V2)
    assert result.disposition is AbsoluteDispositionV2.FAIL
    assert "retry" not in result.model_dump(mode="json")
```

- [ ] **Step 2: Run rubric tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_rubric.py -q`

Expected: collection fails because the rubric module does not exist.

- [ ] **Step 3: Define and implement rubric `attorney-eval-v2`**

Use explicit fixed values:

```python
RUBRIC_V2 = RubricV2(
    version="attorney-eval-v2",
    importance_weights={"critical": 3, "material": 2, "supporting": 1},
    critical_recall_floor=1.0,
    weighted_coverage_floor=0.90,
    material_unsupported_assertions_allowed=0,
)

DISPOSITION_CREDIT = {
    "met": 1.0,
    "partially_met": 0.5,
    "not_met": 0.0,
    "uncertain": 0.0,
}
```

Return `INCONCLUSIVE` before scoring for unresolved material baseline disputes, a grader-reported baseline defect, `uncertain`, missing/duplicate grades, passage ambiguity, or material grader disagreement. Return `FAIL` for critical recall below `1.0`, weighted coverage below `0.90`, or any material unsupported assertion. Return `PASS` only when every gate passes.

Material agreement requires identical per-requirement dispositions and
identical unsupported-assertion identities after exact report-passage
resolution, including assertion importance. Any baseline-defect flag from
either grader is independently sufficient for `INCONCLUSIVE`. Rationale text
and supporting passages may differ when the substantive disposition agrees;
retain both observations without synthesizing a third rationale.

- [ ] **Step 4: Implement deterministic reconciliation artifacts**

Preserve both accepted grader observations; do not synthesize new legal reasoning:

```python
def reconcile_grades(
    baseline: CanonicalBaselineV2,
    first: GradeResponseV2,
    second: GradeResponseV2,
    report_text: str,
) -> ReconciledGradeV2:
    first_snapshot = validate_grade_response(baseline, first, report_text)
    second_snapshot = validate_grade_response(baseline, second, report_text)
    if _material_disagreement(first_snapshot, second_snapshot):
        return ReconciledGradeV2.inconclusive(
            "GRADER_DISAGREEMENT", first_snapshot, second_snapshot
        )
    return _agreed_findings(first_snapshot, second_snapshot)
```

For two reports, derive `candidate_win`, `comparator_win`, `tie`, or `neither` only when both absolute dispositions are conclusive. If either is `INCONCLUSIVE`, the comparison is `INCONCLUSIVE`.

- [ ] **Step 5: Run focused and legacy scoring tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_rubric.py tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_scoring.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v2_rubric.py tests/evaluation/test_attorney_v2_rubric.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v2_rubric.py
```

Expected: all pass; protocol 1.3 scoring fixtures remain byte-stable.

- [ ] **Step 6: Commit**

```bash
git add src/regulatory_harvest/evaluation/attorney_v2_rubric.py \
  tests/evaluation/test_attorney_v2_rubric.py
git commit -m "feat: reconcile simplified report grades"
```

---

### Task 5: Add protocol 2.0 atomic storage and replay verification

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_artifacts.py`
- Create: `tests/evaluation/test_attorney_v2_artifacts.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_artifacts.py`

**Interfaces:**
- Consumes: existing race-resistant `_RunStorage` implementation and protocol 2.0 manifest/artifact models.
- Produces: `initialize_v2_run_storage`, `commit_v2_transition`, `load_verified_v2_run`, `verify_v2_run`, and `detect_evaluation_protocol`.

- [ ] **Step 1: Write storage and replay RED tests**

Cover canonical initialization, atomic accepted transition, refused-response no-write, manifest/artifact hash mismatch, unknown/additional file, symlink containment, root alias behavior, cyclic/oversized manifest input, and protocol detection:

```python
def test_refused_v2_response_leaves_run_tree_unchanged(tmp_path: Path) -> None:
    run = initialized_v2_run(tmp_path)
    before = tree_snapshot(run)
    result = preflight_v2_response(run, malformed_response())
    assert not result.valid
    assert tree_snapshot(run) == before


def test_protocol_detection_keeps_legacy_replay_separate(tmp_path: Path) -> None:
    assert detect_evaluation_protocol(v2_run(tmp_path)) == "2.0"
    assert detect_evaluation_protocol(retained_v1_3_run(tmp_path)) == "1.3"
```

- [ ] **Step 2: Run artifact tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_artifacts.py -q`

Expected: collection fails because the v2 artifact module does not exist.

- [ ] **Step 3: Promote the minimum shared secure-storage interface**

In `attorney_artifacts.py`, expose narrow internal-package wrappers without changing 1.3 behavior:

```python
RunStorage = _RunStorage
open_evaluation_storage = _open_run_storage
atomic_write_evaluation_artifact = _atomic_write
read_evaluation_artifact = _read_artifact
```

Keep the POSIX no-follow, root-identity, inventory, and atomic-replace implementation unchanged. Add a 1.3 regression proving the promoted names produce identical reads and writes.

- [ ] **Step 4: Implement the protocol 2.0 manifest verifier**

Verify canonical bytes, exact artifact inventory, artifact hashes, call/request/response bindings, one pending-call cardinality, operation/phase consistency, terminal-result consistency, compiler/rubric fingerprints, and root identity before exposing state or allowing mutation.

```python
def verify_v2_run(run_dir: Path) -> EvaluationVerification: ...

def load_verified_v2_run(
    run_dir: Path,
) -> tuple[EvaluationManifestV2, EvaluationResultV2 | None]: ...

def commit_v2_transition(
    storage: RunStorage,
    manifest: EvaluationManifestV2,
    files: Mapping[str, bytes],
) -> EvaluationManifestV2: ...
```

- [ ] **Step 5: Run v2 and retained v1.3 integrity suites**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_artifacts.py tests/evaluation/test_attorney_artifacts.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_artifacts.py src/regulatory_harvest/evaluation/attorney_v2_artifacts.py tests/evaluation/test_attorney_v2_artifacts.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_artifacts.py src/regulatory_harvest/evaluation/attorney_v2_artifacts.py
```

- [ ] **Step 6: Commit**

```bash
git add src/regulatory_harvest/evaluation/attorney_artifacts.py \
  src/regulatory_harvest/evaluation/attorney_v2_artifacts.py \
  tests/evaluation/test_attorney_v2_artifacts.py
git commit -m "feat: seal evaluator protocol 2 runs"
```

---

### Task 6: Implement the bounded full-runtime protocol 2.0 workflow

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v2_workflow.py`
- Create: `tests/evaluation/test_attorney_v2_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: v2 models, compiler, request builders, rubric, artifacts, existing `freeze_case`, and generation-capsule verification.
- Produces: `initialize_evaluation_v2`, `resume_evaluation_v2`, `next_evaluator_request_v2`, `preflight_evaluator_response_v2`, `guarded_submit_evaluator_response_v2`, `submit_evaluator_response_v2`, `stop_evaluation_v2_inconclusive`, and `run_evaluation_v2`.

- [ ] **Step 1: Write workflow RED tests as a transition table**

Cover no-audit and disputed-audit paths, one/two candidates, grader agreement/disagreement, one mechanical repair, repeated mechanical failure, valid fail acceptance, exact operation order, fresh-context labels, no rejected-response artifacts, and no grade referee:

```python
@pytest.mark.parametrize(
    ("audit_has_concerns", "labels", "operations"),
    [
        (False, ["A"], ["source_review", "source_audit", "grade_report", "grade_report"]),
        (
            True,
            ["A", "B"],
            [
                "source_review",
                "source_audit",
                "source_referee",
                "grade_report",
                "grade_report",
                "grade_report",
                "grade_report",
            ],
        ),
    ],
)
def test_v2_operation_sequence(
    audit_has_concerns: bool,
    labels: list[str],
    operations: list[str],
) -> None:
    completed = run_scripted_v2_case(audit_has_concerns, labels)
    assert [call.operation.value for call in completed.manifest.calls] == operations
```

- [ ] **Step 2: Run workflow tests and witness RED**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_v2_workflow.py -q`

Expected: collection fails because the workflow module does not exist.

- [ ] **Step 3: Implement initialization and verified resume**

Initialization accepts only case schema `1.1`, reopens generation capsules, freezes the blinded case, writes protocol/rubric/build bindings, and creates exactly one `source_review` request. It does not initialize a protocol 1.3 admission role.

```python
def initialize_evaluation_v2(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationRunStateV2: ...
```

- [ ] **Step 4: Implement accepted transitions**

Use a closed phase table:

```python
TRANSITIONS = {
    EvaluationPhaseV2.SOURCE_REVIEW: EvaluatorOperationV2.SOURCE_REVIEW,
    EvaluationPhaseV2.SOURCE_AUDIT: EvaluatorOperationV2.SOURCE_AUDIT,
    EvaluationPhaseV2.SOURCE_REFEREE: EvaluatorOperationV2.SOURCE_REFEREE,
    EvaluationPhaseV2.GRADE: EvaluatorOperationV2.GRADE_REPORT,
}
```

After review, request audit. After empty audit, compile. After nonempty audit, request one referee response covering all disputes, then compile. Grade A twice, then B twice when present. Reconcile and score only after both grades for a report exist. Seal terminal results once.

- [ ] **Step 5: Implement bounded mechanical repair**

Every mechanical preflight failure leaves the run tree byte-identical. The
controller keeps the per-call attempt count in its active orchestration context
and sends the identical request packet to one fresh repair role. After the
second failure, it invokes a separate terminal transition that stores only
`MECHANICAL_RESPONSE_INVALID`; it never stores refused response bytes,
field-specific details, or a third attempt.

```python
def stop_evaluation_v2_inconclusive(
    run_dir: Path,
    reason: Literal["MECHANICAL_RESPONSE_INVALID"],
) -> EvaluationRunStateV2: ...
```

- [ ] **Step 6: Implement the async convenience runner**

```python
@runtime_checkable
class AttorneyEvaluatorV2(Protocol):
    async def evaluate(self, request: EvaluatorRequestV2) -> EvaluatorResponseV2: ...


async def run_evaluation_v2(
    case: AttorneyEvaluationCase,
    evaluator: AttorneyEvaluatorV2,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> CompletedEvaluationV2: ...
```

- [ ] **Step 7: Export the public protocol 2.0 workflow**

Export the seven workflow functions and `AttorneyEvaluatorV2` from `evaluation/__init__.py`. Do not export a protocol 1.3 initializer as the default API.

- [ ] **Step 8: Run focused, neighboring, and static tests**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_v2_workflow.py \
  tests/evaluation/test_attorney_v2_artifacts.py \
  tests/evaluation/test_attorney_workflow.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation tests/evaluation
.venv/bin/mypy src/regulatory_harvest/evaluation
```

- [ ] **Step 9: Commit**

```bash
git add src/regulatory_harvest/evaluation/attorney_v2_workflow.py \
  src/regulatory_harvest/evaluation/__init__.py \
  tests/evaluation/test_attorney_v2_workflow.py
git commit -m "feat: run bounded evaluator protocol 2"
```

---

### Task 7: Route new CLI runs to 2.0 and retain 1.3 verification

**Files:**
- Modify: `scripts/attorney_eval_full.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/cli/test_eval_cli.py`

**Interfaces:**
- Consumes: `detect_evaluation_protocol` and both protocol workflow/verifier surfaces.
- Produces: public commands `eval-init`, `eval-next`, `eval-preflight`, `eval-submit`, `eval-submit-safe`, `eval-stop-inconclusive`, `eval-status`, and `eval-verify`, with protocol-aware dispatch.

- [ ] **Step 1: Write CLI routing RED tests**

Prove `eval-init` creates a 2.0 manifest, every subsequent command dispatches by sealed manifest, an unknown protocol fails safely, and a retained 1.3 fixture remains status/verify readable but cannot be resumed through 2.0:

```python
def test_eval_init_defaults_to_protocol_2(tmp_path: Path) -> None:
    result = run_full("eval-init", case_fixture(), tmp_path / "run")
    assert result.returncode == 0
    assert read_json(tmp_path / "run" / "manifest.json")["protocol_version"] == "2.0"


def test_retained_protocol_1_3_run_verifies_without_migration(tmp_path: Path) -> None:
    run = materialize_retained_v1_3_run(tmp_path)
    before = tree_snapshot(run)
    assert run_full("eval-verify", run=run).returncode == 0
    assert tree_snapshot(run) == before
```

- [ ] **Step 2: Run routing tests and witness RED**

Run:

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py -q \
  -k 'protocol_2 or protocol_1_3_replay'
```

Expected: `eval-init` still creates protocol 1.3.

- [ ] **Step 3: Add protocol-aware dispatch**

Import 2.0 initialization for new runs. For existing runs, inspect only canonical bounded manifest bytes and route:

```python
protocol = detect_evaluation_protocol(Path(args.run))
if protocol == "2.0":
    return _dispatch_v2(args)
if protocol == "1.3":
    return _dispatch_v1_3_read_or_verify(args)
raise EvaluationCliInputError("EVALUATION_PROTOCOL_UNSUPPORTED", "...")
```

Permit only 1.3 `eval-status` and `eval-verify`. Every mutation command against a 1.3 run returns a stable legacy-read-only diagnostic. New `eval-init` has no `--protocol 1.3` escape hatch.

`eval-stop-inconclusive` accepts only the stable reason
`MECHANICAL_RESPONSE_INVALID`, verifies the still-pending 2.0 run, and performs
the separate terminal transition after the controller has observed two
write-free refusals.

- [ ] **Step 4: Update the local scripted evaluator harness**

Change `attorney_cli.py` scripted fixtures to provide semantic review/audit/grade responses and run `run_evaluation_v2`. Keep one retained 1.3 fixture solely for replay and tamper tests.

- [ ] **Step 5: Run complete full-runtime CLI suites**

Run:

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py \
  tests/evaluation/test_attorney_v2_workflow.py -q
.venv/bin/ruff check scripts/attorney_eval_full.py \
  src/regulatory_harvest/evaluation/attorney_cli.py \
  tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_cli.py scripts/attorney_eval_full.py
```

- [ ] **Step 6: Commit**

```bash
git add scripts/attorney_eval_full.py \
  src/regulatory_harvest/evaluation/attorney_cli.py \
  tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py
git commit -m "feat: default evaluation CLI to protocol 2"
```

---

### Task 8: Mirror protocol 2.0 in the stdlib-only portable runtime

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: protocol 2.0 canonical model shapes and full-runtime golden vectors.
- Produces: portable protocol detection, parsing, compilation, rubric, state transitions, guarded submission, status, and replay with exact full-runtime parity.

- [ ] **Step 1: Add full/portable differential RED vectors**

Create table-driven vectors for:

```python
V2_PARITY_VECTORS = (
    "empty_audit_single_report_pass",
    "audited_correction_pair_fail_and_pass",
    "unresolved_source_dispute",
    "grader_disagreement",
    "material_unsupported_assertion",
    "ambiguous_source_quote",
    "ambiguous_report_quote",
    "first_mechanical_repair",
    "second_mechanical_failure",
    "tampered_baseline",
    "unknown_protocol",
    "retained_protocol_1_3_replay",
)
```

For every vector assert exact stdout, stderr, exit code, manifest, artifact bytes, result bytes, root hash, and no-mutation parity.

- [ ] **Step 2: Run differential tests and witness RED**

Run:

```bash
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py -q -k 'v2_parity or protocol_1_3_replay'
```

Expected: portable rejects protocol 2.0 or emits protocol 1.3 bytes.

- [ ] **Step 3: Implement compact portable semantic validators**

Reuse the portable script's bounded JSON, strict scalar, canonical encoding,
hashing, safe-path, and atomic-write primitives. Add only the four 2.0 inner
payload validators. Do not port Pydantic schemas or protocol 1.3 ledger repair
logic into the 2.0 path.

```python
def _portable_v2_source_review(value: object) -> dict[str, object]: ...
def _portable_v2_source_audit(value: object) -> dict[str, object]: ...
def _portable_v2_source_referee(value: object) -> dict[str, object]: ...
def _portable_v2_grade(value: object) -> dict[str, object]: ...
```

- [ ] **Step 4: Mirror compilation and rubric algorithms exactly**

Use the same canonical sort tuples, ID formats, unique exact-quote resolution,
relationship resolution, weights, thresholds, disagreement rules, and
fingerprint exclusions as the full runtime. Keep these functions in one
contiguous protocol 2.0 section so reviewers can compare them directly with
the focused full modules.

- [ ] **Step 5: Mirror the bounded workflow and legacy detector**

New portable `eval-init` creates 2.0. Existing run commands dispatch by the
sealed manifest. Retained 1.3 replay keeps its current compatibility branch.
The portable path must never import site packages and must work with
`python3 -I -S`.

- [ ] **Step 6: Run the portable and combined suites**

Run:

```bash
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py -q
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py \
  tests/evaluation/test_attorney_v2_models.py \
  tests/evaluation/test_attorney_v2_compiler.py \
  tests/evaluation/test_attorney_v2_requests.py \
  tests/evaluation/test_attorney_v2_rubric.py \
  tests/evaluation/test_attorney_v2_artifacts.py \
  tests/evaluation/test_attorney_v2_workflow.py -q
python3 -I -S scripts/attorney_eval_portable.py eval-init --help
python3 -I -S scripts/attorney_eval_portable.py eval-verify --help
.venv/bin/ruff check scripts/attorney_eval_portable.py tests/scripts/test_attorney_eval_portable.py
```

- [ ] **Step 7: Check the 2.0 size budget before commit**

Count new full modules plus the portable protocol 2.0 section. Expected: no
more than `12,689` lines. If over budget, remove duplicated helpers and schema
prose before proceeding; do not weaken tests or integrity controls to meet the
budget.

- [ ] **Step 8: Commit**

```bash
git add scripts/attorney_eval_portable.py \
  tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py
git commit -m "feat: mirror evaluator protocol 2 portably"
```

---

### Task 9: Package and document the simplified evaluator boundary

**Files:**
- Modify: `scripts/skill-package-files.txt`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/skill/test_skill_package.py`
- Create: `assets/attorney-evaluation-v2-response.template.json`
- Modify: `references/attorney-evaluation.md`
- Modify: `docs/evaluation.md`
- Modify: `docs/roadmap.md`
- Modify: `README.md`
- Modify: `docs/verification/evaluator-2.0-baseline.md`

**Interfaces:**
- Consumes: completed full and portable 2.0 runtime.
- Produces: an exact package allowlist, public protocol documentation, response template, post-implementation simplification metrics, and reproducible archive assertions.

- [ ] **Step 1: Write package/documentation RED tests**

Assert the manifest contains each new full-runtime module exactly once, both
clean package builds contain byte-identical copies, public docs state the
bounded meaning of dispositions, and the response template uses the seven-key
outer envelope without a fixed inner payload:

```python
def test_packaged_protocol_2_contract_is_complete() -> None:
    joined = packaged_text("docs/evaluation.md", "references/attorney-evaluation.md")
    assert "PASS means the report satisfied this versioned evaluation rubric" in joined
    assert "does not establish legal correctness" in joined
    assert "at most one fresh mechanical repair" in joined
```

- [ ] **Step 2: Run package tests and witness RED**

Run:

```bash
.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py -q \
  -k 'protocol_2 or evaluator_response_template'
```

Expected: new modules are absent from the allowlist and docs still describe
the protocol 1.3 ledger-repair flow as current.

- [ ] **Step 3: Update the exact package allowlist and template**

Add these sorted entries:

```text
src/regulatory_harvest/evaluation/attorney_v2_artifacts.py
src/regulatory_harvest/evaluation/attorney_v2_compiler.py
src/regulatory_harvest/evaluation/attorney_v2_models.py
src/regulatory_harvest/evaluation/attorney_v2_requests.py
src/regulatory_harvest/evaluation/attorney_v2_rubric.py
src/regulatory_harvest/evaluation/attorney_v2_workflow.py
assets/attorney-evaluation-v2-response.template.json
```

Keep the new 2.0 outer response template generic; the pending request remains
the authority for the operation-specific inner payload schema. Leave the
existing response template byte-stable for qualification and retained 1.3
workflows.

- [ ] **Step 4: Update public documentation**

Document the four substantive roles, deterministic compiler, two-grader
agreement rule, one-repair limit, 2.0 default, 1.3 replay-only boundary, and
narrow disposition meaning. State that requirement-level findings are the
primary product and attorney review remains required. Replace the roadmap item
with a completed-design/in-progress implementation entry rather than deleting
the historical beta lesson.

- [ ] **Step 5: Record post-implementation metrics**

Re-run the baseline commands and add a comparison table. Require all targets
from Task 1 to pass. Also record public synthetic mechanical refusal rates for
1.3 and 2.0 fixtures; do not serialize private prompts, sources, or rejected
responses.

- [ ] **Step 6: Run package, documentation, and repository gates**

Run:

```bash
.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py -q
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
python3 scripts/build_skill.py --output /tmp/regulatory-harvest-v2-a.zip
python3 scripts/build_skill.py --output /tmp/regulatory-harvest-v2-b.zip
cmp /tmp/regulatory-harvest-v2-a.zip /tmp/regulatory-harvest-v2-b.zip
python3 scripts/audit_release.py --archive /tmp/regulatory-harvest-v2-a.zip
```

Expected: full suite, Ruff, mypy, diff, reproducibility, ZIP integrity, package
membership, and privacy audit all pass.

- [ ] **Step 7: Commit**

```bash
git add scripts/skill-package-files.txt tests/scripts/test_build_skill.py \
  tests/skill/test_skill_package.py \
  assets/attorney-evaluation-v2-response.template.json \
  references/attorney-evaluation.md docs/evaluation.md docs/roadmap.md \
  docs/verification/evaluator-2.0-baseline.md README.md
git commit -m "docs: publish simplified evaluator protocol"
```

---

### Task 10: Prove the end-to-end readiness gate

**Files:**
- Create: `tests/fixtures/attorney-eval-v2/case.json`
- Create: `tests/fixtures/attorney-eval-v2/scripted-responses.json`
- Create: `docs/verification/evaluator-2.0.md`
- Modify: `tests/cli/test_eval_cli.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`

**Interfaces:**
- Consumes: exact packaged protocol 2.0 full/portable runtimes.
- Produces: a complete fictional public-safe scripted run, a fresh isolated-role readiness receipt, and the final protocol-ready decision.

- [ ] **Step 1: Write a full fictional end-to-end RED test**

The fixture must include an obligation, exception, deadline, enforcement
consequence, one source gap, one supported report passage, one omission, and a
paired report comparison. Exercise review, nonempty audit, referee, two graders
per report, rubric, terminal result, status, and replay:

```python
def test_protocol_2_completes_full_and_portable_end_to_end(tmp_path: Path) -> None:
    full = run_scripted_protocol_2("full", tmp_path / "full")
    portable = run_scripted_protocol_2("portable-isolated", tmp_path / "portable")
    assert full.returncode == portable.returncode == 0
    assert full.stdout == portable.stdout
    assert read_result(tmp_path / "full") == read_result(tmp_path / "portable")
    assert verify_root(tmp_path / "full") == verify_root(tmp_path / "portable")
```

- [ ] **Step 2: Run the end-to-end test and witness RED**

Run:

```bash
.venv/bin/pytest tests/cli/test_eval_cli.py \
  tests/scripts/test_attorney_eval_portable.py -q -k 'protocol_2_completes'
```

Expected: the fixture is not yet bound to the exact response/request sequence.

- [ ] **Step 3: Bind the fictional scripted responses to actual requests**

Generate requests with the full runtime, author only the semantic payloads,
copy actual request fingerprints into the outer envelopes, and keep strict
fixture comparison enabled. Do not weaken the scripted judge to ignore request
bytes or fingerprints.

- [ ] **Step 4: Run the public readiness matrix**

Run:

```bash
.venv/bin/pytest tests/cli/test_eval_cli.py \
  tests/scripts/test_attorney_eval_portable.py -q -k 'protocol_2_completes'
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
```

Expected: all pass, with exact full/portable terminal artifacts and replay.

- [ ] **Step 5: Build and bind the exact commit twice**

Commit the fictional fixture and tests, then build from two detached no-local
clones of that exact commit. Require identical ZIP bytes, member lists, member
bytes, clean extractions, full help, `python3 -I -S` portable help, and zero
automated privacy findings.

```bash
git add tests/fixtures/attorney-eval-v2 tests/cli/test_eval_cli.py \
  tests/scripts/test_attorney_eval_portable.py docs/verification/evaluator-2.0.md
git commit -m "test: prove evaluator protocol 2 end to end"
```

- [ ] **Step 6: Run one fresh frozen evaluation with isolated roles**

Use exactly the reviewed commit, reproducible archive, installed member bytes,
qualified source bytes, generation capsule, and approved candidate/comparator.
Use fresh contexts for reviewer, auditor, any source referee, and both graders
per report. Permit only one fresh mechanical repair per call. Do not substitute
a case, candidate, or additional role. Do not publish private inputs or role
responses.

- [ ] **Step 7: Apply the hard readiness decision**

Mark protocol 2.0 ready only if the fresh evaluation reaches a terminal
substantive disposition, all artifacts replay in full and isolated portable
runtimes, all deterministic gates pass, and the simplification targets remain
met. If the run stops mechanically or with unresolved grader disagreement,
record the public-safe reason and keep protocol 2.0 experimental and nondefault.

- [ ] **Step 8: Final verification commit when the readiness receipt changes docs**

If the public-safe receipt changes `docs/verification/evaluator-2.0.md`, run the
full suite, Ruff, mypy, package reproducibility, and privacy audit again, then
commit only that verified receipt:

```bash
git add docs/verification/evaluator-2.0.md
git commit -m "docs: record evaluator protocol 2 readiness"
```
