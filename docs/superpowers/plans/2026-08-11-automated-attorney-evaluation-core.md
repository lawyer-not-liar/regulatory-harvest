# Automated Attorney Evaluation Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the provider-neutral public Python core that admits evaluation cases, seals source-only legal ledgers, validates blind grades, calculates absolute and comparative outcomes, and writes immutable evaluation artifacts.

**Architecture:** Add a new attorney-evaluation subsystem beside the existing LegalBench-RAG retrieval evaluator. Strict Pydantic models define every case, judge response, score, and result. Deterministic modules own validation, fingerprints, state transitions, scoring, and rendering; a caller-supplied `AttorneyEvaluationJudge` owns model judgments.

**Tech Stack:** Python 3.11+, Pydantic 2.8+, pytest, Hypothesis where useful, Ruff, mypy, existing canonical JSON and SHA-256 helpers.

## Global Constraints

- Keep LegalBench-RAG separate; do not combine retrieval metrics with attorney-evaluation scores.
- Add no required dependency, model vendor, API key, search provider, database, n8n workflow, SurrealDB service, or MCP server.
- Treat source text and reports as caller-owned local data; add no telemetry or publication path.
- Never use a comparator or legacy report as legal ground truth.
- Build and seal the legal ledger before exposing report text to grading operations.
- Keep absolute `PASS` or `FAIL` distinct from comparative win, tie, loss, or neither.
- Preserve `CASE_INVALID` and `INCONCLUSIVE`; never force a score from inadequate evidence.
- Use `attorney-eval-v1` weights and thresholds exactly as approved in the design.
- Preserve existing bundle schema `1.0`, LegalBench-RAG behavior, and current CLI exit codes.
- Public fixtures must be synthetic and contain no private matter, source, report, rating, mapping, or retained hash.
- Do not publish, push, merge, or contact an external service.

---

## File map

- Create `src/regulatory_harvest/evaluation/attorney_models.py`: controlled vocabulary and strict public evaluation models.
- Create `src/regulatory_harvest/evaluation/attorney_admission.py`: case freezing, deterministic admission checks, and readiness aggregation.
- Create `src/regulatory_harvest/evaluation/attorney_ledger.py`: exact-span ledger validation, audit resolution, and sealing.
- Create `src/regulatory_harvest/evaluation/attorney_grading.py`: blind grade validation, claim inventory validation, and referee dispute selection.
- Create `src/regulatory_harvest/evaluation/attorney_scoring.py`: versioned absolute and comparative score calculation.
- Create `src/regulatory_harvest/evaluation/attorney_workflow.py`: provider-neutral judge protocol and state machine.
- Create `src/regulatory_harvest/evaluation/attorney_artifacts.py`: atomic immutable run storage, hash verification, resume, and Markdown rendering.
- Create `src/regulatory_harvest/evaluation/attorney_cli.py`: `harvest eval attorney` command handling.
- Modify `src/regulatory_harvest/evaluation/__init__.py`: export the public attorney-evaluation API.
- Modify `src/regulatory_harvest/evaluation/cli.py`: route LegalBench-RAG and attorney evaluation without changing LegalBench behavior.
- Modify `src/regulatory_harvest/cli.py`: register attorney subcommands and stable exit semantics.
- Create focused tests under `tests/evaluation/` and CLI tests under `tests/cli/`.
- Create synthetic fixtures under `tests/fixtures/attorney-eval/`.
- Modify `docs/evaluation.md`: document the separate benchmark scopes and public API.

### Task 1: Strict attorney-evaluation data contracts

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Test: `tests/evaluation/test_attorney_models.py`

**Interfaces:**
- Consumes: `StrictModel`, `SourceRole`, `SourceQuality`, and `canonical_json_bytes`.
- Produces: `RequestedAuthority`, `EvaluationSource`, `CandidateReport`,
  `AttorneyEvaluationCase`, `BlindAssignment`, `CaseEnvelope`, `EvaluationIssue`,
  `JudgeRequest`, `JudgeResponse`, `AdmissionCheck`, `CaseAdmissionJudgment`,
  `CaseReadiness`, `LedgerCitation`, `LedgerEntry`, `LedgerGap`, `LegalLedger`,
  `LedgerDispute`, `LedgerAudit`, `SealedLedger`, `EntryGrade`,
  `OutOfLedgerClaim`, `NarrativeScore`, `CandidateGrade`, `RefereeDecision`,
  `DeterministicChecks`, `EvaluationRubric`, `ReportEvaluation`,
  `ComparisonEvaluation`, `AttorneyEvaluationResult`, `JudgeCallRecord`,
  `ArtifactRecord`, `EvaluationManifest`, `EvaluationRunState`,
  `model_fingerprint`, and the controlled enums listed below.

- [ ] **Step 1: Write failing strict-model and fingerprint tests**

```python
def test_case_envelope_rejects_unknown_fields_and_has_stable_fingerprint() -> None:
    case = synthetic_case()
    assert model_fingerprint(case) == model_fingerprint(case)
    envelope = synthetic_envelope(case_fingerprint=model_fingerprint(case))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CaseEnvelope.model_validate(
            {**envelope.model_dump(mode="json"), "surprise": True}
        )


def test_comparator_is_never_marked_as_ground_truth() -> None:
    case = synthetic_case()
    assert {candidate.role for candidate in case.candidates} == {
        CandidateRole.CANDIDATE,
        CandidateRole.COMPARATOR,
    }
    assert not hasattr(case, "answer_report_id")
```

- [ ] **Step 2: Run the model tests and verify red**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_models.py -q`

Expected: FAIL during import because `attorney_models` and its public types do not exist.

- [ ] **Step 3: Implement the controlled vocabulary and strict models**

Create string enums for:

```python
class EvaluationMode(StrEnum):
    CURRENT_LAW = "current-law"
    CLOSED_UNIVERSE = "closed-universe"


class ReadinessStatus(StrEnum):
    ADMITTED = "ADMITTED"
    CASE_INVALID = "CASE_INVALID"
    INCONCLUSIVE = "INCONCLUSIVE"


class Materiality(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class CoverageDisposition(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    OVERSTATED = "OVERSTATED"
    CONTRADICTED = "CONTRADICTED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
```

Define these remaining enums exactly:

```python
class LedgerCategory(StrEnum):
    STATUS = "status"
    SCOPE = "scope"
    DEFINITION = "definition"
    REQUIREMENT = "requirement"
    PROHIBITION = "prohibition"
    RIGHT = "right"
    EXCEPTION = "exception"
    DEADLINE = "deadline"
    ENFORCEMENT = "enforcement"
    REMEDY = "remedy"
    PENALTY = "penalty"
    APPEAL = "appeal"
    IMPLEMENTATION = "implementation"


class CandidateRole(StrEnum):
    CANDIDATE = "candidate"
    COMPARATOR = "comparator"


class AbsoluteDisposition(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    CASE_INVALID = "CASE_INVALID"


class ComparativeDisposition(StrEnum):
    REGULATORY_HARVEST_WIN = "REGULATORY_HARVEST_WIN"
    COMPARATOR_WIN = "COMPARATOR_WIN"
    TIE = "TIE"
    NEITHER = "NEITHER"
    INCONCLUSIVE = "INCONCLUSIVE"
    CASE_INVALID = "CASE_INVALID"


class JudgeOperation(StrEnum):
    ADMIT_CASE = "admit_case"
    BUILD_LEDGER = "build_ledger"
    AUDIT_LEDGER = "audit_ledger"
    REPAIR_LEDGER = "repair_ledger"
    GRADE_REPORT = "grade_report"
    REFEREE = "referee"


class JudgeIsolation(StrEnum):
    FRESH_CONTEXT = "fresh_context"
    SEQUENTIAL_SAME_CONTEXT = "sequential_same_context"
    SCRIPTED_FIXTURE = "scripted_fixture"


class IssueSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
```

Define strict models with these fields:

```python
class EvaluationSource(StrictModel):
    source_id: str
    title: str
    normalized_text: str
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_url: str | None = None
    publisher: str | None = None
    jurisdiction: str
    authority_type: str
    source_role: SourceRole
    source_quality: SourceQuality
    completeness: Literal["complete", "consolidated", "amending", "partial", "snippet", "unknown"]
    language: str
    version: str | None = None
    effective_date: str | None = None
    supersession: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)


class CandidateReport(StrictModel):
    candidate_id: str
    role: CandidateRole
    report_text: str
    report_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_json: dict[str, object] | None = None
    validation_receipt: dict[str, object] | None = None
    coverage_review: dict[str, object] | None = None


class AttorneyEvaluationCase(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    mode: EvaluationMode
    question: str
    jurisdiction: str
    as_of: date
    requested_authorities: list[RequestedAuthority] = Field(min_length=1)
    sources: list[EvaluationSource] = Field(min_length=1)
    candidates: list[CandidateReport] = Field(min_length=1, max_length=2)
    client_facts: str | None = None
    rubric_version: Literal["attorney-eval-v1"] = "attorney-eval-v1"


class BlindAssignment(StrictModel):
    anonymous_label: Literal["A", "B"]
    candidate_id: str


class CaseEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case: AttorneyEvaluationCase
    assignments: list[BlindAssignment]
    case_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    seed_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvaluationIssue(StrictModel):
    code: str
    severity: IssueSeverity
    message: str
    related_ids: list[str] = Field(default_factory=list)


class JudgeRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation: JudgeOperation
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_instructions: str
    json_schema: dict[str, object]
    payload: dict[str, object]
    safe_metadata: dict[str, str] = Field(default_factory=dict)


class JudgeResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation: JudgeOperation
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_name: str
    model_name: str
    judge_isolation: JudgeIsolation
    payload: dict[str, object]
    response_id: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)


class AdmissionCheck(StrictModel):
    code: str
    satisfied: bool
    material: bool
    rationale: str
    source_ids: list[str] = Field(default_factory=list)


class CaseAdmissionJudgment(StrictModel):
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    checks: list[AdmissionCheck]
    issues: list[EvaluationIssue] = Field(default_factory=list)


class CaseReadiness(StrictModel):
    status: ReadinessStatus
    case_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    judgment_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_codes: list[str] = Field(default_factory=list)
    rationale: str


class LedgerCitation(StrictModel):
    source_id: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    quote: str


class LedgerEntry(StrictModel):
    ledger_id: str
    walk_order: int = Field(ge=0)
    category: LedgerCategory
    materiality: Materiality
    actor: str | None = None
    modality: str
    operative_action: str
    object: str | None = None
    trigger: str | None = None
    threshold: str | None = None
    conditions: list[str] = Field(default_factory=list)
    exceptions: list[str] = Field(default_factory=list)
    timing: str | None = None
    enforcing_authority: str | None = None
    enforcement_route: str | None = None
    consequence: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)
    proposition: str
    materiality_rationale: str
    citations: list[LedgerCitation] = Field(min_length=1)


class LedgerGap(StrictModel):
    gap_id: str
    category: LedgerCategory
    message: str
    source_ids: list[str] = Field(default_factory=list)


class LegalLedger(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    entries: list[LedgerEntry]
    gaps: list[LedgerGap] = Field(default_factory=list)


class LedgerDispute(StrictModel):
    dispute_id: str
    action: Literal["add", "edit", "delete", "split", "merge", "materiality"]
    target_ledger_ids: list[str] = Field(default_factory=list)
    proposed_entries: list[LedgerEntry] = Field(default_factory=list)
    materiality: Materiality
    rationale: str


class LedgerAudit(StrictModel):
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    disputes: list[LedgerDispute] = Field(default_factory=list)
    complete: bool


class SealedLedger(StrictModel):
    ledger: LegalLedger
    audit_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    ledger_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class EntryGrade(StrictModel):
    ledger_id: str
    disposition: CoverageDisposition
    rationale: str
    report_location: str | None = None


class OutOfLedgerClaim(StrictModel):
    claim_id: str
    claim_text: str
    report_location: str
    disposition: CoverageDisposition
    category: LedgerCategory
    materiality: Materiality
    related_ledger_ids: list[str] = Field(default_factory=list)
    rationale: str


class NarrativeScore(StrictModel):
    dimension: Literal[
        "executive_summary", "regulatory_walk", "key_requirements",
        "penalties_enforcement", "qualification_placement",
        "requirements_workplan_boundary", "limitations", "scanability"
    ]
    score: int = Field(ge=1, le=4)
    rationale: str


class CandidateGrade(StrictModel):
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    anonymous_label: Literal["A", "B"]
    ledger_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_grades: list[EntryGrade]
    out_of_ledger_claims: list[OutOfLedgerClaim] = Field(default_factory=list)
    narrative_scores: list[NarrativeScore]


class RefereeDecision(StrictModel):
    dispute_id: str
    selected_disposition: CoverageDisposition | None = None
    selected_ledger_resolution: Literal["accept_a", "accept_b", "replace"] | None = None
    replacement_entries: list[LedgerEntry] = Field(default_factory=list)
    rationale: str
    source_ids: list[str] = Field(default_factory=list)


class DeterministicChecks(StrictModel):
    anonymous_label: Literal["A", "B"]
    valid: bool
    critical_codes: list[str] = Field(default_factory=list)
    issues: list[EvaluationIssue] = Field(default_factory=list)


class EvaluationRubric(StrictModel):
    version: Literal["attorney-eval-v1"]
    materiality_weights: dict[Materiality, int]
    critical_recall_floor: float
    weighted_recall_floor: float
    claim_precision_floor: float
    walk_average_floor: float
    walk_dimension_floor: int
    comparison_weights: dict[Literal["recall", "precision", "walk"], float]
    comparison_margin: float


class ReportEvaluation(StrictModel):
    anonymous_label: Literal["A", "B"]
    absolute_disposition: AbsoluteDisposition
    weighted_recall: float
    claim_precision: float
    walk_average: float
    normalized_score: float
    critical_defect: bool
    blocking_codes: list[str] = Field(default_factory=list)


class ComparisonEvaluation(StrictModel):
    disposition: ComparativeDisposition
    winner_label: Literal["A", "B"] | None = None
    score_difference: float | None = None
    rationale_codes: list[str] = Field(default_factory=list)


class AttorneyEvaluationResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    rubric: EvaluationRubric
    readiness: CaseReadiness
    reports: list[ReportEvaluation]
    comparison: ComparisonEvaluation | None = None
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
```

Validate safe unique identifiers, nonblank legal text, source and report hashes,
one candidate plus at most one comparator, and exact source hash equality. Add a
`model_fingerprint(value: StrictModel, *, exclude: set[str] | None = None) -> str`
helper that hashes canonical JSON after removing named self-hash fields. Define
`JudgeCallRecord`, `ArtifactRecord`, `EvaluationManifest`, and
`EvaluationRunState` with exact operation, attempt, request/response fingerprint,
artifact path/hash, state, retry-count, and terminal-status fields needed by Task
5. Re-export only the intended public types.

- [ ] **Step 4: Run focused tests and type checking**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_models.py -q`

Expected: PASS.

Run: `.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_models.py`

Expected: PASS with no issues.

- [ ] **Step 5: Commit the contract layer**

```bash
git add src/regulatory_harvest/evaluation/attorney_models.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_models.py
git commit -m "feat: add attorney evaluation contracts"
```

### Task 2: Case freezing and fail-closed admission

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_admission.py`
- Test: `tests/evaluation/test_attorney_admission.py`

**Interfaces:**
- Consumes: `AttorneyEvaluationCase`, `CaseAdmissionJudgment`, `CaseEnvelope`, and `CaseReadiness` from Task 1.
- Produces: `freeze_case(case: AttorneyEvaluationCase, *, seed_hex: str) -> CaseEnvelope`, `build_admission_packet(envelope: CaseEnvelope) -> JudgeRequest`, and `adjudicate_admission(envelope: CaseEnvelope, judgment: CaseAdmissionJudgment) -> CaseReadiness`.

- [ ] **Step 1: Write failing admission tests for the observed failure classes**

```python
@pytest.mark.parametrize(
    ("issue_code", "expected"),
    [
        ("AUTHORITY_MISMATCH", ReadinessStatus.CASE_INVALID),
        ("OPERATIVE_TEXT_MISSING", ReadinessStatus.CASE_INVALID),
        ("CURRENTNESS_EVIDENCE_INSUFFICIENT", ReadinessStatus.CASE_INVALID),
        ("LANGUAGE_UNRESOLVED", ReadinessStatus.CASE_INVALID),
        ("SOURCE_PARITY_UNPROVEN", ReadinessStatus.CASE_INVALID),
    ],
)
def test_material_admission_issue_invalidates_case(issue_code, expected) -> None:
    envelope = freeze_case(synthetic_case(), seed_hex="1" * 64)
    judgment = admission_judgment(issue_codes=[issue_code])
    readiness = adjudicate_admission(envelope, judgment)
    assert readiness.status is expected
    assert readiness.issue_codes == [issue_code]


def test_export_presence_cannot_prove_case_source_parity() -> None:
    case = synthetic_case_with_unmatched_fulltext_export_metadata()
    readiness = adjudicate_admission(
        freeze_case(case, seed_hex="2" * 64),
        admission_judgment(common_record_proven=False),
    )
    assert readiness.status is ReadinessStatus.CASE_INVALID
    assert "SOURCE_PARITY_UNPROVEN" in readiness.issue_codes
```

- [ ] **Step 2: Run the admission tests and verify red**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_admission.py -q`

Expected: FAIL because admission functions are unavailable.

- [ ] **Step 3: Implement case freezing and deterministic prechecks**

`freeze_case` must:

```python
def freeze_case(case: AttorneyEvaluationCase, *, seed_hex: str) -> CaseEnvelope:
    _validate_seed(seed_hex)
    _validate_source_hashes(case.sources)
    _validate_report_hashes(case.candidates)
    assignments = _blind_assignments(case.candidates, seed_hex)
    payload = case.model_dump(mode="json")
    case_fingerprint = sha256_digest(canonical_json_bytes(payload))
    return CaseEnvelope(
        case=case,
        assignments=assignments,
        case_fingerprint=case_fingerprint,
    )
```

Add deterministic issue codes for invalid hashes, duplicate sources, empty or
snippet-only primary records, missing requested-authority metadata, unsupported
language declarations, and comparator access mismatches. Build a source-only
judge packet with no candidate report text, report identifier, or system name.

`adjudicate_admission` must combine deterministic issues with the strict model
judgment. Any material readiness issue returns `CASE_INVALID`. Invalid judge
output is handled by the workflow retry policy in Task 5, not silently accepted.

- [ ] **Step 4: Run admission and model tests**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_admission.py tests/evaluation/test_attorney_models.py -q`

Expected: PASS.

- [ ] **Step 5: Commit admission**

```bash
git add src/regulatory_harvest/evaluation/attorney_admission.py tests/evaluation/test_attorney_admission.py
git commit -m "feat: add attorney evaluation admission gate"
```

### Task 3: Source-only ledger validation, audit, and sealing

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_ledger.py`
- Test: `tests/evaluation/test_attorney_ledger.py`

**Interfaces:**
- Consumes: admitted `CaseEnvelope`, `LegalLedger`, `LedgerAudit`, and optional `RefereeDecision`.
- Produces: `validate_ledger(envelope: CaseEnvelope, ledger: LegalLedger) -> list[EvaluationIssue]`, `ledger_disputes(audit: LedgerAudit) -> list[LedgerDispute]`, and `seal_ledger(envelope: CaseEnvelope, ledger: LegalLedger, audit: LedgerAudit, referee: RefereeDecision | None) -> SealedLedger`.

- [ ] **Step 1: Write failing exact-evidence and completeness tests**

```python
def test_ledger_entry_requires_exact_source_slice() -> None:
    envelope = admitted_envelope()
    ledger = ledger_with_quote("controller shall document")
    issues = validate_ledger(envelope, ledger)
    assert {issue.code for issue in issues} == {"LEDGER_QUOTE_MISMATCH"}


def test_unresolved_critical_audit_dispute_is_inconclusive() -> None:
    with pytest.raises(LedgerInconclusiveError, match="critical ledger dispute"):
        seal_ledger(
            admitted_envelope(),
            valid_ledger(),
            audit_with_critical_omission(),
            referee=None,
        )
```

- [ ] **Step 2: Run ledger tests and verify red**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_ledger.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement ledger validation and sealing**

Validate every exact span using half-open offsets:

```python
def _quote_matches(source: EvaluationSource, span: LedgerCitation) -> bool:
    return (
        0 <= span.start_char < span.end_char <= len(source.normalized_text)
        and source.normalized_text[span.start_char:span.end_char] == span.quote
    )
```

Require unique ledger IDs, at least one exact citation per operative entry,
valid relationship targets, category-specific fields, and a concrete rationale
for materiality. Require enforcement and penalty entries to identify their
trigger or relationship to the triggering entry. Reject commentary-only support
for operative rules.

Apply the ledger audit as structured additions, edits, deletions, splits, merges,
and materiality changes. A referee decision must name an existing dispute and
select one allowed resolution. Hash the final ledger with the case fingerprint
and audit fingerprint. The sealed model must not contain candidate report text.

- [ ] **Step 4: Run ledger tests and source validation regressions**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_ledger.py tests/validation/test_bundle.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the ledger layer**

```bash
git add src/regulatory_harvest/evaluation/attorney_ledger.py tests/evaluation/test_attorney_ledger.py
git commit -m "feat: seal source-only legal ledgers"
```

### Task 4: Blind grading, referee routing, and deterministic scoring

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_grading.py`
- Create: `src/regulatory_harvest/evaluation/attorney_scoring.py`
- Test: `tests/evaluation/test_attorney_grading.py`
- Test: `tests/evaluation/test_attorney_scoring.py`

**Interfaces:**
- Consumes: `SealedLedger`, two `CandidateGrade` objects per report, optional `RefereeDecision` objects, and deterministic report issues.
- Produces: `validate_grade`, `material_disputes`, `resolve_grades`, `score_report`, and `compare_reports`.

- [ ] **Step 1: Write failing grade-completeness and safety-gate tests**

```python
def test_grade_must_dispose_every_applicable_ledger_entry_once() -> None:
    issues = validate_grade(sealed_ledger_with_ids("L1", "L2"), grade_for_ids("L1"))
    assert {issue.code for issue in issues} == {"GRADE_LEDGER_ENTRY_MISSING"}


def test_unsupported_material_penalty_blocks_absolute_pass() -> None:
    evaluation = score_report(
        sealed_ledger(),
        resolved_grade_with_unsupported_material_penalty(),
        deterministic_checks(valid=True),
        RUBRIC_V1,
    )
    assert evaluation.absolute_disposition is AbsoluteDisposition.FAIL
    assert "UNSUPPORTED_MATERIAL_PENALTY" in evaluation.blocking_codes


def test_narrative_cannot_outvote_critical_legal_error() -> None:
    strong_prose = report_evaluation(score=99.0, critical_defect=True)
    sound_report = report_evaluation(score=80.0, critical_defect=False)
    assert compare_reports(strong_prose, sound_report).winner_id == sound_report.candidate_id
```

- [ ] **Step 2: Run grading and scoring tests and verify red**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_scoring.py -q`

Expected: FAIL because grading and scoring functions do not exist.

- [ ] **Step 3: Implement grade validation and dispute selection**

`validate_grade` must require one disposition for each applicable ledger entry,
validate report locations, reject unknown ledger IDs, validate out-of-ledger
claim findings, and require eight narrative dimensions scored from 1 through 4.

`material_disputes` must return only disagreements that can change a critical
gate, absolute threshold, comparative five-point margin, or confidence. Use this
decision rule:

```python
def disposition_credit(value: CoverageDisposition) -> float:
    return {
        CoverageDisposition.COMPLETE: 1.0,
        CoverageDisposition.PARTIAL: 0.5,
        CoverageDisposition.MISSING: 0.0,
        CoverageDisposition.OVERSTATED: 0.0,
        CoverageDisposition.CONTRADICTED: 0.0,
        CoverageDisposition.UNSUPPORTED: 0.0,
        CoverageDisposition.NOT_APPLICABLE: 0.0,
    }[value]
```

Resolve exact agreements deterministically. Require a referee result for each
material disagreement. Preserve both grader rationales and the final referee
rationale in the audit artifact.

- [ ] **Step 4: Implement `attorney-eval-v1` scoring exactly**

Define immutable rubric constants:

```python
RUBRIC_V1 = EvaluationRubric(
    version="attorney-eval-v1",
    materiality_weights={"critical": 5, "material": 3, "supporting": 1},
    critical_recall_floor=1.0,
    weighted_recall_floor=0.90,
    claim_precision_floor=0.95,
    walk_average_floor=3.0,
    walk_dimension_floor=2,
    comparison_weights={"recall": 0.45, "precision": 0.25, "walk": 0.30},
    comparison_margin=5.0,
)
```

Compute weighted recall and claim precision from separate denominators. Apply
critical gates before calculating a comparative winner. Return `NEITHER` when
both reports have critical defects, and `TIE` when the safe normalized scores
differ by less than five percentage points.

- [ ] **Step 5: Run focused tests, property tests, Ruff, and mypy**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_scoring.py -q`

Expected: PASS.

Run: `.venv/bin/ruff check --no-cache src/regulatory_harvest/evaluation/attorney_grading.py src/regulatory_harvest/evaluation/attorney_scoring.py tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_scoring.py`

Expected: PASS.

Run: `.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_grading.py src/regulatory_harvest/evaluation/attorney_scoring.py`

Expected: PASS.

- [ ] **Step 6: Commit grading and scoring**

```bash
git add src/regulatory_harvest/evaluation/attorney_grading.py src/regulatory_harvest/evaluation/attorney_scoring.py tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_scoring.py
git commit -m "feat: score blind attorney evaluations"
```

### Task 5: Immutable workflow, artifacts, and provider-neutral judge protocol

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Create: `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- Test: `tests/evaluation/test_attorney_workflow.py`
- Test: `tests/evaluation/test_attorney_artifacts.py`

**Interfaces:**
- Consumes: all prior task functions and models.
- Produces: `AttorneyEvaluationJudge`, `initialize_evaluation`,
  `next_judge_request`, `submit_judge_response`, `run_evaluation`,
  `resume_evaluation`, `verify_evaluation_run`, and
  `render_evaluation_report` with these signatures:

```python
def initialize_evaluation(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
) -> EvaluationRunState: ...

def next_judge_request(run_dir: Path) -> JudgeRequest | None: ...

def submit_judge_response(
    run_dir: Path,
    response: JudgeResponse,
) -> EvaluationRunState: ...

async def run_evaluation(
    case: AttorneyEvaluationCase,
    judge: AttorneyEvaluationJudge,
    output_dir: Path,
    *,
    seed_hex: str,
) -> CompletedEvaluation: ...

def resume_evaluation(run_dir: Path) -> EvaluationRunState: ...

def verify_evaluation_run(run_dir: Path) -> EvaluationVerification: ...

def render_evaluation_report(result: AttorneyEvaluationResult) -> str: ...
```

Define `CompletedEvaluation(result, manifest, run_dir)` and
`EvaluationVerification(valid, issues, root_hash)` as frozen dataclasses in
`attorney_workflow.py` and `attorney_artifacts.py`, respectively.

- [ ] **Step 1: Write failing state-machine and immutability tests**

```python
class ScriptedJudge:
    def __init__(self, responses: dict[JudgeOperation, list[JudgeResponse]]) -> None:
        self.responses = responses
        self.requests: list[JudgeRequest] = []

    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        self.requests.append(request)
        return self.responses[request.operation].pop(0)


@pytest.mark.asyncio
async def test_workflow_seals_ledger_before_report_grading(tmp_path: Path) -> None:
    judge = ScriptedJudge(valid_responses())
    result = await run_evaluation(
        synthetic_case(), judge, tmp_path, seed_hex="4" * 64
    )
    grade_requests = [
        request for request in judge.requests
        if request.operation is JudgeOperation.GRADE_REPORT
    ]
    assert result.manifest.legal_ledger_hash
    assert grade_requests
    assert all(
        request.safe_metadata["legal_ledger_hash"]
        == result.manifest.legal_ledger_hash
        for request in grade_requests
    )


def test_resume_rejects_changed_completed_artifact(tmp_path: Path) -> None:
    run = write_completed_fixture(tmp_path)
    (run / "legal-ledger.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvaluationIntegrityError, match="artifact hash"):
        resume_evaluation(run)
```

- [ ] **Step 2: Run workflow tests and verify red**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_artifacts.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the judge protocol and bounded workflow**

Define:

```python
@runtime_checkable
class AttorneyEvaluationJudge(Protocol):
    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        """Return one strict response for one blinded evaluation operation."""
        raise NotImplementedError
```

Use these transitions:

```text
created -> admission -> ledger-build -> ledger-audit -> ledger-repair?
        -> ledger-referee? -> ledger-sealed -> grade-a -> grade-b
        -> report-referee? -> aggregate -> completed
```

Each operation gets a prompt fingerprint, model/provider metadata, response hash,
attempt number, and isolation declaration. Permit one repair attempt after an
invalid structured response. A second invalid response creates an explicit
`INCONCLUSIVE` result and preserves the invalid-response diagnostics.

- [ ] **Step 4: Implement atomic run storage and Markdown rendering**

Write each artifact to a same-directory temporary file, flush and `fsync`, then
replace the target. Refuse to overwrite a completed artifact with different
bytes. `verify_evaluation_run` must recompute every artifact hash and the manifest
root hash.

Render a concise report with this fixed top-level order:

```markdown
# Automated Attorney Evaluation

## Disposition
## Case Readiness
## Critical Defects
## Requirement-by-Requirement Matrix
## Unsupported or Overstated Claims
## Regulatory Walk
## Comparative Result
## Evaluation Limits and Provenance
```

Do not include sealed A/B identities until aggregation is complete.

- [ ] **Step 5: Run workflow, artifact, and existing evaluation tests**

Run: `.venv/bin/pytest tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_artifacts.py tests/evaluation/test_runner.py -q`

Expected: PASS.

- [ ] **Step 6: Commit workflow and artifacts**

```bash
git add src/regulatory_harvest/evaluation/attorney_workflow.py src/regulatory_harvest/evaluation/attorney_artifacts.py tests/evaluation/test_attorney_workflow.py tests/evaluation/test_attorney_artifacts.py
git commit -m "feat: orchestrate immutable attorney evaluations"
```

### Task 6A: Preserve attorney-relevant semantic findings

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_grading.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_scoring.py`
- Test: `tests/evaluation/test_attorney_models.py`
- Test: `tests/evaluation/test_attorney_grading.py`
- Test: `tests/evaluation/test_attorney_scoring.py`
- Test: `tests/evaluation/test_attorney_workflow.py`
- Test: `tests/evaluation/test_attorney_artifacts.py`

The Task 6 mutation audit established that four approved defects could not be
represented by the existing grade/result contracts.  Add closed, typed finding
codes to `EntryGrade` and `NarrativeScore`, and add deduplicated `issue_codes`
to `ReportEvaluation`.  Support exactly:

- `CRITICAL_LEDGER_ENTRY_MISSING` only for a missing critical entry;
- `MATERIAL_EXCEPTION_MISSING` only for a missing material-or-critical
  exception;
- `CONSEQUENCE_TRIGGER_DETACHED` only for a partial, overstated, or
  contradicted penalty, enforcement, or remedy entry whose authoritative
  ledger structure supplies the trigger and consequence relationship; and
- `KEY_REQUIREMENTS_ACTION_PLAN` only for a score of 1 or 2 on
  `key_requirements` or `requirements_workplan_boundary`.

Unknown, duplicate, or context-inconsistent findings make a grade invalid or
inconclusive.  Finding disagreements must enter the normal dispute/referee
path, the selected finding set must survive resolution and immutable replay,
and tampering must fail fingerprint/artifact verification.  Scoring exposes
the selected findings as issue codes without changing existing metrics,
blocking codes, floors, safety gates, or comparative behavior.

Use TDD, run the model/grading/scoring/workflow/artifact focused suites plus
Ruff and mypy, and commit this contract amendment separately before Task 6.

### Task 6: CLI, synthetic mutation suite, documentation, and core verification

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Create: `tests/fixtures/attorney-eval/case.json`
- Create: `tests/fixtures/attorney-eval/sources/synthetic-rule.txt`
- Create: `tests/fixtures/attorney-eval/reports/correct.md`
- Create: `tests/fixtures/attorney-eval/reports/missing-duty.md`
- Create: `tests/fixtures/attorney-eval/responses/scripted-responses.json`
- Create: `tests/evaluation/test_attorney_mutations.py`
- Modify: `src/regulatory_harvest/evaluation/cli.py`
- Modify: `src/regulatory_harvest/cli.py`
- Modify: `tests/cli/test_eval_cli.py`
- Modify: `docs/evaluation.md`

**Interfaces:**
- Consumes: `run_evaluation`, `resume_evaluation`, and `verify_evaluation_run`.
- Produces: `harvest eval attorney run`, `harvest eval attorney verify`, and stable JSON exit output.

- [ ] **Step 1: Write failing CLI and mutation tests**

```python
def test_attorney_eval_cli_runs_scripted_synthetic_case(tmp_path: Path) -> None:
    status = main([
        "eval", "attorney", "run",
        "--case", str(FIXTURE / "case.json"),
        "--scripted-responses", str(FIXTURE / "responses" / "scripted-responses.json"),
        "--output", str(tmp_path / "run"),
        "--json",
    ])
    assert status == 0
    result = json.loads((tmp_path / "run" / "evaluation-result.json").read_text())
    assert result["reports"][0]["absolute_disposition"] == "PASS"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing-critical-duty", "CRITICAL_LEDGER_ENTRY_MISSING"),
        ("invented-penalty", "UNSUPPORTED_MATERIAL_PENALTY"),
        ("wrong-instrument", "AUTHORITY_MISMATCH"),
        ("snippet-only", "OPERATIVE_TEXT_MISSING"),
        ("unresolved-language", "LANGUAGE_UNRESOLVED"),
    ],
)
def test_synthetic_mutation_has_expected_failure(mutation, expected_code) -> None:
    result = run_mutation_fixture(mutation)
    assert expected_code in result.all_issue_codes
```

- [ ] **Step 2: Run CLI and mutation tests and verify red**

Run: `.venv/bin/pytest tests/cli/test_eval_cli.py tests/evaluation/test_attorney_mutations.py -q`

Expected: FAIL because the attorney subcommand and fixtures are unavailable.

- [ ] **Step 3: Implement attorney CLI routing and stable exits**

Register `attorney` beside `legalbench-rag`. Use:

- exit `0` for completed evaluations whose required candidate reports pass;
- exit `2` for invalid inputs;
- exit `3` for `CASE_INVALID` or `INCONCLUSIVE`;
- exit `4` for a completed required candidate `FAIL`; and
- exit `5` for run-integrity failure.

The test-only `--scripted-responses` adapter must be clearly labeled as a local
fixture mechanism and reject paths outside the supplied fixture directory. The
production public API remains the `AttorneyEvaluationJudge` protocol.

- [ ] **Step 4: Add synthetic fixtures and mutation builders**

Use an original CC0-marked synthetic rule containing one actor, two duties, one
exception, one deadline, one enforcement route, and one penalty. Record its
license in `tests/fixtures/FIXTURE_LICENSES.md`. Generate every mutation from the
base fixture in test code so each expected defect is isolated.

- [ ] **Step 5: Document the benchmark boundary and commands**

Update `docs/evaluation.md` with separate sections for:

- LegalBench-RAG retrieval evaluation;
- attorney-report evaluation scope;
- case admission;
- judge protocol;
- absolute and comparative outcomes;
- local-only artifacts; and
- limits of automated legal evaluation.

State that the evaluator measures compliance with its supplied source record and
rubric and does not establish that legal advice is correct or complete.

- [ ] **Step 6: Run focused and full public verification**

Run: `.venv/bin/pytest tests/evaluation tests/cli/test_eval_cli.py -q`

Expected: PASS.

Run: `.venv/bin/pytest -q`

Expected: all tests pass except any already documented intentional skip.

Run: `.venv/bin/ruff check --no-cache .`

Expected: PASS.

Run: `.venv/bin/mypy src/regulatory_harvest`

Expected: PASS.

- [ ] **Step 7: Commit the public core integration**

```bash
git add src/regulatory_harvest/evaluation src/regulatory_harvest/cli.py tests/evaluation tests/cli/test_eval_cli.py tests/fixtures/attorney-eval tests/fixtures/FIXTURE_LICENSES.md docs/evaluation.md
git commit -m "feat: add automated attorney evaluation core"
```

### Task 7: Replace the aggregate-only matrix with an evidence-level comparison

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py` only if a new public renderer is exported
- Test: `tests/evaluation/test_attorney_models.py`
- Test: `tests/evaluation/test_attorney_artifacts.py`
- Test: `tests/evaluation/test_attorney_workflow.py`

The completed renderer currently labels an aggregate score table as a
"Requirement-by-Requirement Matrix." That does not satisfy the attorney-facing
comparison goal. Replace it with a deterministic, immutable, replay-verified
matrix containing one row per sealed ledger entry in `walk_order` and stable
`ledger_id` order. Each row must include:

- ledger ID, category, materiality, and the source-grounded legal proposition;
- compact citation pins to the exact retained source spans;
- for each anonymous report, the resolved disposition, report location,
  semantic finding codes, and concise selected rationale; and
- an explicit absent value when a second report was not supplied.

Keep aggregate recall and precision in a separately and accurately named score
summary. Preserve anonymous A/B labels in public artifacts. Escape Markdown
table content deterministically, including pipes, backslashes, CR/LF, and
control characters. A completed run must fail verification if any matrix field
differs from the sealed ledger or resolved grades. Invalid and inconclusive runs
must render an explicit unavailable matrix without fabricating rows.

Because the terminal result contract changes, advance the persisted evaluation
artifact schema from `1.1` to `1.2`; keep the outer host response envelope at
`1.0`. Reject mixed `1.1`/`1.2` run artifacts with the existing stable
unsupported-schema integrity code. Update documentation and every full-core
golden expectation that binds the persisted artifact schema.

Use TDD. Verify focused model, artifact, workflow, CLI, mutation, and full
evaluation suites plus Ruff and mypy. Commit this amendment separately before
the portable mirror and skill instructions.

### Task 7B: Normalize accepted judge responses during integrity replay

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- Test: `tests/evaluation/test_attorney_artifacts.py`
- Test: `tests/evaluation/test_attorney_workflow.py` where an in-progress replay is exercised
- Modify portable substrate/tests only if differential replay requires it

A real host journey exposed a replay defect after an otherwise valid grade was
accepted. The response omitted optional empty `finding_codes`; Pydantic
normalized those defaults into the persisted grade artifact, but verification
compared the normalized artifact with the raw response dictionary and reported
an integrity failure. Replay must compare the same strictly validated,
normalized model semantics used at acceptance while preserving the immutable
raw response artifact and all hash, inventory, schema, and unknown-field gates.

Audit every accepted operation that directly compares a raw response payload
with a normalized semantic artifact, including ledger repair and both referee
branches. Add full/portable differential tests for omitted valid defaults,
in-progress status/resume, terminal verification, and tampering. Do not weaken
strict schemas or allow a response that acceptance would reject. Use TDD and
commit this repair separately before resuming the Task 2 forward journey.

### Task 7C: Bind exact input bytes and independent candidate source access

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `scripts/harvest_portable.py`
- Modify relevant full/portable/skill case-fixture tests and synthetic fixtures
- Modify Task 2 case template/reference only where the strict filesystem schema changes

Fresh Task 2 review proved that both filesystem loaders used `.strip()` before
hashing sources and reports. Files differing only by trailing newline therefore
collapsed to one case fingerprint. Content-bearing model validators also
stripped these values. Preserve exact valid UTF-8 content, reject blank content
without changing it, and derive hashes from the exact retained bytes.

The filesystem adapter must also stop manufacturing every candidate's source
parity receipt from the common source hashes. Extend its strict case input with
candidate-specific preserved source-access paths (without user-authored hash
placeholders), hash those inputs independently, and use those commitments for
admission. Missing or mismatched candidate access must fail closed as unproven
parity; it may not be inferred from the common packet. Keep the admission packet
source-only and the candidate identities blinded.

Use TDD with full/portable differential vectors for leading/trailing whitespace,
CRLF/LF differences, UTF-8 BOM/content, candidate report bytes, candidate-access
match/mismatch/missing evidence, symlink/race boundaries, fingerprints, resume,
and terminal verification. Update the public-safe template to the actual schema,
rerun an admitted two-report host journey, and commit separately before Task 3.

## Core-plan completion gate

- Every focused and full test above passes.
- LegalBench-RAG fixture fingerprints and outputs remain unchanged.
- The public tree contains only synthetic evaluation content.
- A correct synthetic report passes; every controlled defect yields its expected
  blocking code or readiness disposition.
- Repeated evaluation with the same case, responses, seed, and rubric yields the
  same deterministic artifacts.
- No skill-package or private-workshop file changes are included in this phase.
