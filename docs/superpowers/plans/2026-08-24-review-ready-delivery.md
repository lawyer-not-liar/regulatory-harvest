# Review-Ready Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the opt-in `delivery-readiness-v1` companion protocol that grades each report revision through two fresh lanes locked to a verified stable baseline, derives a Protocol 2.2-strict-equivalent disposition and one of three independent attorney-review readiness tiers, and emits a deterministic, evidence-grounded gap-and-follow-up handoff without changing any retained protocol bytes or defaults.

**Architecture:** Consume, but never rebuild, `VerifiedBaselineContextV1` from the prerequisite stable-baseline plan. Load the terminal qualification capsule separately through its exclusive verified loader, cross-bind it to the baseline's qualification, source-record, and legal-input identities, and persist only a path-free typed projection of its admission/readiness evidence and per-source language treatments. A separate readiness graph snapshots and binds that exact baseline, qualification evidence, generation capsule, deterministic validation receipt, and revised report; it runs two fresh baseline-locked grading lanes under the exact retained Protocol 2.2 scoring and sensitivity semantics, then two fresh report-wide safety lanes and dispute-scoped safety referees. A verified Protocol 2.2 result may be attached as historical cross-check evidence, but it is never required and never supplies authoritative grades for the new report. Full and isolated-portable runtimes share one packaged rubric/scoring-contract asset and must produce byte-identical requests, accepted responses, grader aggregates, strict-equivalent result, safety artifacts, matrices, Markdown, manifests, status, verification, and complete trees.

**Tech Stack:** Python 3.11+, Pydantic v2 strict models, canonical JSON and SHA-256 helpers, existing descriptor-anchored evaluation storage, asyncio workflow drivers, argparse JSON CLI, pytest/pytest-asyncio/Hypothesis, Ruff, mypy, isolated `python -I -S`, deterministic ZIP packaging.

**Spec:** `docs/superpowers/specs/2026-08-24-review-ready-delivery-design.md`

**Prerequisite plan:** `docs/superpowers/plans/2026-08-24-stable-evaluation-baseline.md` must be implemented first. This plan consumes its exact `load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1`, `project_gradeable_baseline_v1(context) -> GradeableBaselineProjectionV1`, and `verify_gradeable_baseline_projection_v1(context, candidate) -> GradeableBaselineProjectionV1` entry points and does not duplicate baseline source review, audit, referee, correction, identity, projection, or reuse logic.

## Global Constraints

- Protocols 1.3, 2.0, 2.1, and 2.2 remain byte-for-byte replay-only; their dispositions, exit codes, manifests, results, run trees, public JSON keys, fixtures, and commands do not change.
- Protocol 2.1 remains the default. `delivery-readiness-v1` is a separate, opt-in, experimental companion and implementation alone does not authorize publication, a default change, production-maturity claims, or client delivery.
- Delivery readiness has exactly three wire values: `HIGH_ASSURANCE`, `REVIEW_READY_WITH_GAPS`, and fail-closed `NOT_DELIVERABLE`.
- Fresh authoritative grading emits `baseline_locked_strict_equivalent_disposition: PASS | FAIL | INCONCLUSIVE` under exact retained Protocol 2.2 scoring, lane-merging, and contested-baseline sensitivity semantics. It is explicitly labeled strict-equivalent, not represented as a retained Protocol 2.2 result.
- When supplied, an existing verified Protocol 2.2 result is preserved separately as `historical_v22_strict_disposition: PASS | FAIL | INCONCLUSIVE`; it is optional cross-check evidence, never rewritten, never silently substituted for fresh grades, and never used to derive the readiness tier.
- `HIGH_ASSURANCE` retains the exact `1.0` critical-recall and `0.90` weighted-coverage floors in both fresh baseline-locked grader lanes and requires fresh strict-equivalent `PASS`.
- `REVIEW_READY_WITH_GAPS` uses the exact conservative minimum-lane weighted-coverage floor `0.70`, with `met=1.0`, `partially_met=0.5`, and `not_met` or `uncertain=0.0`.
- One packaged canonical `readiness-rubric-v1.json` is the only new source of thresholds, the retained-v2.2 scoring-contract fingerprint, disposition weights, rationale kinds, follow-up codes, owner roles, blocking codes, warning copy, and generic-rationale refusals. Full code proves its strict-equivalent fields equal `RUBRIC_V22` and the retained scoring contract; portable code reads the same asset and does not redeclare these values.
- Every partial, missing, uncertain, contested, baseline-gap, safety, qualification, generation, currentness, language, or client-fact shortfall has one controller-issued matrix row; rows may be grouped into actions but never omitted or merged away.
- Every row has evidence-bound `why_unresolved`, `why_it_matters`, and `resolution_test` text. Blank, generic, contradictory, score-only, code-only, or evidence-unbound rationales block delivery; the controller never invents legal rationale text.
- Grading always uses two fresh isolated baseline-locked lanes and never regenerates the stable baseline. Safety review then uses two additional fresh isolated lanes. Any safety disagreement is visible and resolved only by a fresh dispute-scoped referee; no controller branch silently selects the favorable lane.
- Mechanical refusals are write-free. One fresh bounded repair is allowed; a second refusal leaves the exact request pending and exits `6`, never `NOT_DELIVERABLE`.
- Companion artifacts live in a sibling readiness directory under the approved governed control root. No readiness artifact is inserted into or inferred for a retained evaluation or baseline run.
- Every accepted role response, request, matrix, result, Markdown handoff, verification record, and manifest is canonical and replay-derived. No absolute private path, report/source text, provider secret, rejected response, or hidden report label enters public status or verification output.
- Secure storage rejects symlinks, FIFOs, device files, hard-link aliases, replaced roots, unowned paths, rollback races, and unexpected inventory entries. Response controls remain outside immutable roots.
- Attorney handoffs and matrices are private work product. They are not uploaded or web-searched without explicit authorization and always carry the mandatory attorney-review warning.

---

## File Map

New focused runtime files:

- `src/regulatory_harvest/evaluation/readiness-rubric-v1.json` — canonical packaged policy bytes shared by full and portable engines.
- `src/regulatory_harvest/evaluation/attorney_readiness_models.py` — strict wire enums, role packets, matrix/result/state/manifest contracts only.
- `src/regulatory_harvest/evaluation/attorney_readiness_inputs.py` — secure verification and snapshot binding for baseline, generation, validation receipt, revised report, and optional historical Protocol 2.2 cross-check.
- `src/regulatory_harvest/evaluation/attorney_readiness_requests.py` — exact baseline-locked grade-fragment, contested-grade, safety-lane, and safety-referee request builders plus compiler/scoring-contract fingerprints.
- `src/regulatory_harvest/evaluation/attorney_readiness_drafts.py` — bounded grade/safety draft parsing, report/source evidence-handle resolution, generic-rationale refusal, and one-repair outcomes.
- `src/regulatory_harvest/evaluation/attorney_readiness_compiler.py` — fresh grader aggregation, exact v2.2-equivalent scoring/sensitivity, optional historical cross-check, gap inventories, safety reconciliation, matrices, blockers, and three-tier result.
- `src/regulatory_harvest/evaluation/attorney_readiness_handoff.py` — deterministic private Markdown rendering and nondelivery suppression.
- `src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py` — immutable graph initialization, transition commit, exact replay, loading, and verification.
- `src/regulatory_harvest/evaluation/attorney_readiness_workflow.py` — resumable lifecycle, external guarded submission, internal two-attempt driver, and telemetry.

Existing integration files changed only additively:

- `src/regulatory_harvest/evaluation/__init__.py` — exports the new companion API.
- `scripts/attorney_eval_full.py` — adds five `eval-readiness-*` commands without changing retained `eval-*` dispatch.
- `scripts/attorney_eval_portable.py` — dependency-free mirror reading the shared rubric asset.
- `scripts/skill-package-files.txt` and `scripts/build_skill.py` — require every readiness runtime, asset, template, and reference.
- `assets/attorney-delivery-readiness-input.template.json` and `assets/attorney-delivery-readiness-response.template.json` — public bounded input/response examples.
- `docs/evaluation.md`, `README.md`, `SKILL.md`, `references/attorney-evaluation.md`, `references/security-and-privacy.md`, and `docs/release-checklist.md` — opt-in workflow, warnings, storage boundaries, parity/calibration/release gates.

New tests and public synthetic fixtures:

- `tests/evaluation/test_attorney_readiness_models.py`
- `tests/evaluation/test_attorney_readiness_inputs.py`
- `tests/evaluation/test_attorney_readiness_requests.py`
- `tests/evaluation/test_attorney_readiness_drafts.py`
- `tests/evaluation/test_attorney_readiness_compiler.py`
- `tests/evaluation/test_attorney_readiness_handoff.py`
- `tests/evaluation/test_attorney_readiness_artifacts.py`
- `tests/evaluation/test_attorney_readiness_workflow.py`
- `tests/evaluation/test_attorney_readiness_stress.py`
- `tests/fixtures/attorney-readiness-v1/FIXTURE_LICENSE.md`
- `tests/fixtures/attorney-readiness-v1/stable/` — fictional source, report, deterministic validation receipt, and scripted fresh-role drafts covering all three tiers.

---

### Task 1: Canonical Readiness Policy and Strict Wire Models

**Files:**
- Create: `src/regulatory_harvest/evaluation/readiness-rubric-v1.json`
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_models.py`
- Create: `tests/evaluation/test_attorney_readiness_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: `AbsoluteDispositionV2`, `ArtifactRecord`, `RequirementGradeV2` semantics, strict wire-snapshot/rehydration patterns from `attorney_v22_models.py`, and `BaselineImportanceV1`, `ImportanceBasisV1`, `GradeableBaselineProjectionV1`, and `BaselineGradeTargetBindingV1` from the prerequisite baseline plan; no Protocol 2.2 or baseline model is mutated.
- Produces: `READINESS_PROTOCOL_V1`, `Hash`, `RequirementDispositionV1`, `ReadinessStrictModelV1`, `DeliveryReadinessTierV1`, `ReadinessOperationV1`, `ReadinessPhaseV1`, `RationaleKindV1`, `FollowUpCodeV1`, `OwnerRoleV1`, `GapOriginV1`, `GapVisibilityV1`, `SafetyFindingKindV1`, `HistoricalV22CrossCheckStatusV1`, `ReadinessRubricV1`, `GenerationValidationBindingV1`, `ReadinessInputV1`, `ReadinessEvaluatorRequestV1`, `ReadinessEvaluatorResponseV1`, `BaselineLockedGradeBatchV1`, `BaselineLockedGradeFragmentV1`, `BaselineLockedContestedGradeV1`, `BaselineLockedGraderAggregateV1`, `BaselineLockedStrictEquivalentV1`, `HistoricalV22CrossCheckV1`, `SafetyGapCandidateV1`, `SafetyGapAssessmentV1`, `SafetyFindingProposalV1`, `SafetyLaneResponseV1`, `SafetyDisputeV1`, `SafetyRefereeDecisionV1`, `ReconciledSafetyReviewV1`, `RequirementMatrixRowV1`, `RequirementMatrixV1`, `GapFollowUpRowV1`, `GapFollowUpMatrixV1`, `DeliveryReadinessResultV1`, `ReadinessCallRecordV1`, `ReadinessManifestV1`, `ReadinessRunStateV1`, `ReadinessVerificationV1`, and strict `validate_*_v1()` boundaries.

- [ ] **Step 1: Write RED model and policy-asset tests**

Add strict-native-wire tests for all enums, forbidden extras, booleans masquerading as scores, raw and `model_construct()` bypasses, cycles/oversize, unique controller IDs, call provenance, exact artifact sorting, and literal policy inventory. `HistoricalV22CrossCheckStatusV1` has exactly `NOT_PROVIDED`, `BASELINE_NOT_COMPARABLE`, `REPORT_NOT_COMPARABLE`, `MATCH`, and `DISPOSITION_DIFFERS`. Include these boundary assertions:

```python
def test_readiness_policy_has_exact_versioned_thresholds() -> None:
    rubric = load_readiness_rubric_v1()
    assert rubric.version == "delivery-readiness-v1"
    assert rubric.review_ready_weighted_coverage_floor == 0.70
    assert rubric.high_assurance_weighted_coverage_floor == 0.90
    assert rubric.high_assurance_critical_recall_floor == 1.0
    assert rubric.strict_equivalent_scoring_semantics == "attorney-eval-v2.2"
    assert rubric.strict_importance_weights == {
        "critical": 3,
        "material": 2,
        "supporting": 1,
    }
    assert rubric.disposition_credit == {
        "met": 1.0,
        "partially_met": 0.5,
        "not_met": 0.0,
        "uncertain": 0.0,
    }


def test_result_keeps_fresh_historical_and_readiness_dispositions_distinct() -> None:
    result = valid_result(
        baseline_locked_strict_equivalent_disposition="PASS",
        historical_v22_strict_disposition="FAIL",
        delivery_readiness="REVIEW_READY_WITH_GAPS",
    )
    assert result.baseline_locked_strict_equivalent_disposition.value == "PASS"
    assert result.historical_v22_strict_disposition.value == "FAIL"
    assert result.delivery_readiness.value == "REVIEW_READY_WITH_GAPS"
```

Assert the fixed rationale inventory contains exactly the eleven design values and the fixed follow-up inventory contains exactly the eight design values. Assert `GapFollowUpRowV1.status` accepts only `open` or `resolved`, and `SafetyLaneResponseV1` cannot provide `gap_id`, canonical order, fingerprints, conservative disposition, or final blocker precedence.

- [ ] **Step 2: Run the model RED**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_models.py -q
```

Expected: collection fails with `ModuleNotFoundError: regulatory_harvest.evaluation.attorney_readiness_models`.

- [ ] **Step 3: Add the canonical rubric asset**

Create canonical JSON with this exact semantic content, serialized by repository formatting conventions:

```json
{
  "attorney_review_warning": "AI-generated work product may contain errors. A qualified attorney must validate the report, requirements, gaps, authorities, currentness, applicability, and follow-up before legal advice or client delivery.",
  "blocking_codes": [
    "INTEGRITY_OR_PROVENANCE_INVALID",
    "MINIMUM_LANE_COVERAGE_BELOW_FLOOR",
    "MATERIAL_UNSUPPORTED_ASSERTION",
    "BASELINE_CONTRADICTION",
    "HIDDEN_MATERIAL_GAP",
    "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
    "MISLEADING_CURRENTNESS_OR_AUTHORITY",
    "OUTCOME_DETERMINATIVE_CONTEST",
    "MISSING_REQUIRED_FOLLOW_UP",
    "GAP_RATIONALE_INVALID",
    "CRITICAL_DISCLOSURE_INVALID",
    "FALSE_RESOLUTION"
  ],
  "disposition_credit": {
    "met": 1.0,
    "not_met": 0.0,
    "partially_met": 0.5,
    "uncertain": 0.0
  },
  "follow_up_codes": [
    "VERIFY_PRIMARY_AUTHORITY",
    "CONFIRM_CURRENTNESS",
    "RESOLVE_APPLICABILITY_FACT",
    "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS",
    "EXPAND_REQUIREMENT_ANALYSIS",
    "CORRECT_UNSUPPORTED_ASSERTION",
    "RESOLVE_LANGUAGE_LIMITATION",
    "RESOLVE_CONTESTED_INTERPRETATION"
  ],
  "generic_rationales": [
    "more research needed",
    "insufficient information",
    "requirement partially met"
  ],
  "high_assurance_critical_recall_floor": 1.0,
  "high_assurance_weighted_coverage_floor": 0.9,
  "strict_equivalent_scoring_semantics": "attorney-eval-v2.2",
  "strict_importance_weights": {"critical": 3, "material": 2, "supporting": 1},
  "owner_roles": ["reviewing_attorney", "outside_counsel", "research_operator"],
  "rationale_kinds": [
    "REPORT_OMISSION",
    "REPORT_PARTIAL_TREATMENT",
    "SOURCE_ABSENT",
    "SOURCE_AMBIGUOUS",
    "SOURCE_CONFLICT",
    "CURRENTNESS_NOT_ESTABLISHED",
    "APPLICABILITY_FACT_MISSING",
    "LANGUAGE_LIMITATION",
    "CONTESTED_INTERPRETATION",
    "UNSUPPORTED_ASSERTION",
    "SAFETY_REVIEW_FINDING"
  ],
  "review_ready_weighted_coverage_floor": 0.7,
  "version": "delivery-readiness-v1"
}
```

- [ ] **Step 4: Implement strict model contracts and the asset loader**

Use `StrEnum`, `Literal`, bounded tuples, strict Pydantic fields, forbidden extras, and the Protocol 2.2 safe raw-wire rehydration pattern. The central row/result signatures are:

```python
class ReadinessOperationV1(StrEnum):
    BASELINE_LOCKED_GRADE = "baseline_locked_grade"
    BASELINE_LOCKED_CONTESTED_GRADE = "baseline_locked_contested_grade"
    SAFETY_REVIEW = "safety_review"
    SAFETY_REFEREE = "safety_referee"


class ReadinessInputV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"]
    gradeable_baseline: GradeableBaselineProjectionV1
    grade_target_fingerprint: Hash
    report_text: str = Field(strict=True)
    report_hash: Hash
    generation_capsule_root: Hash
    generation_validation: GenerationValidationBindingV1
    readiness_rubric_fingerprint: Hash
    strict_equivalent_scoring_contract_fingerprint: Hash
    historical_v22_cross_check: HistoricalV22CrossCheckV1 | None = None


class GapFollowUpRowV1(ReadinessStrictModelV1):
    gap_id: Annotated[str, Field(pattern=r"^GAP-[0-9]{4}$", strict=True)]
    canonical_order: int = Field(ge=0, strict=True)
    origin: GapOriginV1
    subject_id: str = Field(strict=True)
    kind: str = Field(strict=True)
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...]
    importance_rationale: str = Field(strict=True)
    lane_1_disposition: RequirementDispositionV1 | None = None
    lane_2_disposition: RequirementDispositionV1 | None = None
    conservative_disposition: RequirementDispositionV1 | None = None
    report_passages: tuple[str, ...] = ()
    shortfall_description: str = Field(strict=True)
    rationale_kind: RationaleKindV1
    why_unresolved: str = Field(strict=True)
    why_it_matters: str = Field(strict=True)
    evidence_refs: tuple[str, ...]
    disclosure_location: str | None = Field(default=None, strict=True)
    visibility: GapVisibilityV1
    blocking_code: str | None = Field(default=None, strict=True)
    follow_up_code: FollowUpCodeV1
    resolution_test: str = Field(strict=True)
    owner_role: OwnerRoleV1
    status: Literal["open", "resolved"]
    referee_dispute_id: str | None = Field(default=None, strict=True)
    row_fingerprint: Hash


class DeliveryReadinessResultV1(ReadinessStrictModelV1):
    protocol_version: Literal["delivery-readiness-v1"]
    baseline_locked_strict_equivalent_disposition: AbsoluteDispositionV2
    historical_v22_strict_disposition: AbsoluteDispositionV2 | None
    historical_v22_cross_check_status: HistoricalV22CrossCheckStatusV1
    delivery_readiness: DeliveryReadinessTierV1
    minimum_lane_weighted_coverage: float = Field(ge=0.0, le=1.0, strict=True)
    lane_critical_recall: tuple[float, float]
    lane_weighted_coverage: tuple[float, float]
    requirement_matrix_fingerprint: Hash
    gap_matrix_fingerprint: Hash
    blocking_codes: tuple[str, ...]
    attorney_review_warning: str = Field(strict=True)
    result_fingerprint: Hash
```

`ReadinessInputV1` stores exact copied source/report bytes and sanitized binding values, not filesystem paths. `ReadinessCallRecordV1` has controller-owned `call_id`, `operation`, `state`, request/response paths and fingerprints, attempt, lane, and optional dispute ID; pending calls omit provenance and accepted calls require complete provenance.

- [ ] **Step 5: Export and verify Task 1**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_models.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_models.py tests/evaluation/test_attorney_readiness_models.py src/regulatory_harvest/evaluation/__init__.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_models.py
```

Expected: all pass.

- [ ] **Step 6: Commit the policy/model boundary**

```bash
git add src/regulatory_harvest/evaluation/readiness-rubric-v1.json src/regulatory_harvest/evaluation/attorney_readiness_models.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_readiness_models.py
git commit -m "feat: define delivery readiness contracts"
```

---

### Task 2: Verified Baseline, Revised Report, and Optional Historical Input Admission

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_inputs.py`
- Create: `tests/evaluation/test_attorney_readiness_inputs.py`

**Interfaces:**
- Consumes: `load_verified_baseline_run(Path) -> VerifiedBaselineContextV1`; `project_gradeable_baseline_v1(VerifiedBaselineContextV1) -> GradeableBaselineProjectionV1`; `verify_gradeable_baseline_projection_v1(context, candidate) -> GradeableBaselineProjectionV1`; `load_verified_qualification_context(Path) -> VerifiedQualificationContext`; `load_completed_generation_capsule_context(Path)`; canonical `validation-receipt.json`; the Task 1 rubric; and, only when both optional historical arguments are supplied, `load_verified_v22_context(Path) -> VerifiedV22Context` plus `historical_anonymous_label: Literal["A", "B"]`.
- Produces: `VerifiedReadinessInputsV1` and:

```python
def build_verified_readiness_input_v1(
    *,
    baseline_run_dir: Path,
    qualification_run_dir: Path,
    generation_run_dir: Path,
    validation_receipt_path: Path,
    historical_v22_run_dir: Path | None = None,
    historical_anonymous_label: Literal["A", "B"] | None = None,
) -> VerifiedReadinessInputsV1: ...
```

`VerifiedReadinessInputsV1` exposes `readiness_input: ReadinessInputV1`, the exact `baseline_context: VerifiedBaselineContextV1`, verified `gradeable_baseline: GradeableBaselineProjectionV1`, exact `report_text`, `report_hash`, `source_record`, a detached path-free typed qualification projection, qualification/generation/validation bindings, rubric/scoring-contract bytes, and `historical_v22: HistoricalV22CrossCheckV1 | None`. The qualification projection preserves the case schema version; exact admission checks and issues; receipt readiness status, issue codes, and rationale; and exact per-source language-treatment method, rationale, limitations, source IDs, source hashes, and declared/not-declared limitation status. It does not invent a separate qualification finding, infer a limitation from a language code, assert that an undeclared limitation is absent, or expose a filesystem path, provider/role detail, source/report bytes, or duplicate evidence. It exposes no authoritative grader aggregate before the fresh grading workflow runs.

- [ ] **Step 1: Write admission RED tests**

Cover valid admission with no historical run and with one historical run, plus: incomplete baseline; baseline verification false; missing, incomplete, invalid, or non-`ADMITTED` qualification capsule; qualification root/receipt/source-record/legal-input mismatch; duplicate, missing, extra, tampered, or resealed per-source language treatment; an English source with a declared limitation; a non-English source with no declared limitation (preserved as `NOT_DECLARED`, not inferred); generation capsule not completed; generation report hash/bytes mismatch; validation receipt noncanonical/duplicate-key/oversize; receipt status not `completed`; any validation boolean not exactly `true`; coverage-review hash mismatch; validation report path escaping the matter root; symlink/FIFO/hard-link/root replacement; and absolute-path stripping in persisted input. Assert persisted qualification evidence contains checks, issues, receipt readiness, and source-bound language treatments but no qualification path, provider/role identity, duplicate source/report bytes, or invented finding. Optional-history tests cover only-one-argument refusal, pending/non-substantive Protocol 2.2, wrong historical label, result fingerprint/grader/sensitivity tamper, a prior report revision accepted as `REPORT_NOT_COMPARABLE`, exact comparable baseline/report, changed historical baseline, and differing historical disposition.

```python
def test_new_report_requires_no_protocol_22_result(verified_inputs) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.without_history())
    assert admitted.historical_v22 is None
    assert admitted.readiness_input.historical_v22_cross_check is None


def test_historical_fail_is_preserved_without_becoming_fresh_grade(verified_inputs) -> None:
    admitted = build_verified_readiness_input_v1(**verified_inputs.with_historical_fail())
    assert admitted.historical_v22 is not None
    assert admitted.historical_v22.strict_disposition == "FAIL"
    assert not hasattr(admitted, "grader_lanes")


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "review-required"),
        ("evidence_precision_valid", False),
        ("proposition_coverage_valid", False),
        ("provision_recall_valid", False),
    ],
)
def test_generation_validation_must_be_deterministically_complete(
    verified_inputs, field, value
) -> None:
    tree = verified_inputs.with_validation_receipt_update(field, value)
    with pytest.raises(ReadinessInputError, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        build_verified_readiness_input_v1(**tree)
```

- [ ] **Step 2: Run the admission RED**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_inputs.py -q
```

Expected: collection fails because `attorney_readiness_inputs` does not exist.

- [ ] **Step 3: Implement secure graph loading and exact cross-bindings**

The function must perform these checks in this order before a readiness directory exists:

1. Load the baseline exclusively through `load_verified_baseline_run()` and require `context.verification.valid is True`, nonblank `root_hash`, and exact baseline/legal-input fingerprints.
2. Call `project_gradeable_baseline_v1(context)` and immediately round-trip it through `verify_gradeable_baseline_projection_v1(context, projection)`. Preserve its exact `BaselineInputV1`, ordinary/contested requirements (including importance/basis/rationale), relationships, provenance, and `BaselineGradeTargetBindingV1` legal-input, baseline, source-record, semantic-inventory, rubric, policy, compiler, and `grade_target_fingerprint` bindings. Do not serialize `artifact_bytes` wholesale, reimplement projection, or accept a dict-shaped substitute.
3. Load `qualification_run_dir` exclusively through `load_verified_qualification_context()`. Require its manifest root, receipt fingerprint and `ADMITTED` readiness, source-record fingerprint, exact sources, question, jurisdiction, as-of date, and requested authorities to match the verified baseline. Strictly rehydrate and detach its schema-versioned case, admission judgment, and receipt evidence. Emit a path-free qualification projection that preserves checks and issues separately, preserves receipt readiness status/issue codes/rationale as receipt evidence, and binds every schema-1.1 language treatment to exact source IDs/hashes/languages with its exact method/rationale/limitations and explicit `DECLARED` or `NOT_DECLARED` limitation status. Reject missing/extra/duplicate/tampered/resealed treatments and never infer a limitation from language alone.
4. Load the completed generation capsule and treat its exact report bytes/hash as the report newly graded by this readiness run; no Protocol 2.2 label or result is required.
5. Read `validation-receipt.json` through a no-follow, size-bounded, duplicate-key-rejecting anchor rooted at its parent; revalidate the referenced report, bundle, and coverage-review bytes without persisting any receipt path.
6. Require `status == "completed"` and the three named booleans to be native `True`; persist only hashes, counts, status, and booleans in `GenerationValidationBindingV1`.
7. Require both optional historical arguments together or neither. If present, load Protocol 2.2 exclusively through `load_verified_v22_context()`, require a substantive report result for the selected historical label, preserve its exact report hash plus raw `sensitivity.absolute_disposition`, result/manifest/baseline fingerprints, grader aggregates, and reason codes in `HistoricalV22CrossCheckV1`, and require its legal-input bindings to be valid. A historical report hash may differ from the current revised report and is not an admission error.
8. Compare the historical v2.2 baseline's typed semantic projection to the stable baseline and store `baseline_comparable: bool`; separately store `report_comparable: bool` from exact report-hash equality. A differing historical baseline or report remains candid evidence of the old evaluation target and does not block or seed fresh grading. After fresh scoring, the final controller maps absence/comparability/disposition equality to exactly `NOT_PROVIDED`, `BASELINE_NOT_COMPARABLE`, `REPORT_NOT_COMPARABLE`, `MATCH`, or `DISPOSITION_DIFFERS`, with baseline noncomparability taking precedence over report noncomparability. Never guess a crosswalk from similar prose.
9. Persist neither historical report/source duplicates nor any private filesystem path. Historical bytes remain bound by exact hashes/fingerprints and are replayed through the supplied verified run during initialization only; the sanitized immutable cross-check is self-contained thereafter.

Use one explicit constructor for the sanitized receipt binding:

```python
GenerationValidationBindingV1(
    receipt_hash=sha256_digest(receipt_bytes),
    report_hash=sha256_digest(report_bytes),
    bundle_hash=sha256_digest(bundle_bytes),
    coverage_review_hash=sha256_digest(coverage_review_bytes),
    status="completed",
    evidence_precision_valid=True,
    proposition_coverage_valid=True,
    provision_recall_valid=True,
)
```

- [ ] **Step 4: Prove admission is read-only and fail-closed**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_inputs.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_inputs.py tests/evaluation/test_attorney_readiness_inputs.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_inputs.py
```

Expected: all pass; mutation tests confirm no readiness directory or source graph changes occur on any rejected input.

- [ ] **Step 5: Commit verified admission**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_inputs.py tests/evaluation/test_attorney_readiness_inputs.py
git commit -m "feat: bind verified readiness inputs"
```

---

### Task 3: Fresh Baseline-Locked Grading, Gap Inventory, and Safety Request Packets

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_requests.py`
- Create: `tests/evaluation/test_attorney_readiness_requests.py`

**Interfaces:**
- Consumes: `VerifiedReadinessInputsV1`, its verified `GradeableBaselineProjectionV1`, accepted fresh grade fragments/aggregates, `SafetyGapCandidateV1`, accepted safety lane responses, `SafetyDisputeV1`, and the exact packaged rubric/scoring contract from Tasks 1-2.
- Produces: `READINESS_COMPILER_CONTRACT_FINGERPRINT_V1`, `READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1`, `build_baseline_locked_grade_batches_v1()`, `build_baseline_locked_grade_request_v1()`, `build_baseline_locked_contested_grade_request_v1()`, `build_gap_candidate_inventory_v1()`, `build_safety_lane_request_v1()`, `build_safety_disputes_v1()`, and `build_safety_referee_request_v1()`.

```python
def build_baseline_locked_grade_batches_v1(
    baseline: GradeableBaselineProjectionV1,
    *,
    lane: Literal[1, 2],
) -> tuple[BaselineLockedGradeBatchV1, ...]: ...


def build_baseline_locked_grade_request_v1(
    inputs: VerifiedReadinessInputsV1,
    batch: BaselineLockedGradeBatchV1,
) -> ReadinessEvaluatorRequestV1: ...


def build_baseline_locked_contested_grade_request_v1(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: Literal[1, 2],
    contested_requirement_id: str,
) -> ReadinessEvaluatorRequestV1: ...


def build_gap_candidate_inventory_v1(
    inputs: VerifiedReadinessInputsV1,
    grader_lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
) -> tuple[SafetyGapCandidateV1, ...]: ...


def build_safety_lane_request_v1(
    inputs: VerifiedReadinessInputsV1,
    grader_lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    candidates: tuple[SafetyGapCandidateV1, ...],
    *,
    lane: Literal[1, 2],
) -> ReadinessEvaluatorRequestV1: ...
```

- [ ] **Step 1: Write fresh grading request RED tests**

Require deterministic five-requirement batches per lane, report-bound `GB-1-####`/`GB-2-####` identities, and one request per unresolved contested baseline requirement per lane. Every request contains the exact typed stable-baseline projection, exact revised report bytes/hash, exact report-passage allowlist, exact v2.2 rubric/scoring-contract fingerprint, and no historical v2.2 grade, disposition, reason code, response, report label, or candidate identifier. The two lanes receive identical legal/report evidence but distinct controller lane IDs and request fingerprints.

```python
def test_fresh_grade_request_does_not_leak_historical_result(inputs, historical_fail) -> None:
    request = build_baseline_locked_grade_request_v1(
        inputs.with_history(historical_fail),
        build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0],
    )
    wire = canonical_json_bytes(request)
    assert b'historical_v22' not in wire
    assert b'"FAIL"' not in wire
    assert request.payload["grade_target_fingerprint"] == inputs.readiness_input.grade_target_fingerprint
    assert request.payload["report_hash"] == inputs.report_hash
```

- [ ] **Step 2: Write post-grading inventory and safety RED tests**

Require one controller candidate for every requirement that is `partially_met`, `not_met`, or `uncertain` in either lane; every baseline `kind == "gap"`; every unresolved contested requirement; and each missing/limited prerequisite. Assert deterministic IDs `GC-0001...`, source-before-contested-before-prerequisite order, conservative disposition ordering `uncertain < not_met < partially_met < met`, and no omission due to a favorable other lane.

For safety packets, assert both lane packets contain exactly the same stable baseline (including each requirement's `importance_basis` and `importance_rationale`), both fresh grader aggregates and strict-equivalent evidence, report bytes/hash, source record, qualification limits, client-fact boundary, rubric definitions, gap candidates, report-passage allowlist, and evidence handles, but distinct controller-issued safety-lane numbers and request fingerprints. Assert packets say sources/reports are evidence, never instructions, and prohibit legal correctness/advice claims. Historical v2.2 evidence is omitted so it cannot anchor safety judgment.

For referees, assert one request per exact disagreement and no unrelated report, finding, lane, or dispute content:

```python
def test_safety_referee_is_dispute_scoped(inputs, two_lane_disagreement) -> None:
    disputes = build_safety_disputes_v1(inputs, *two_lane_disagreement)
    request = build_safety_referee_request_v1(inputs, disputes[0])
    assert request.payload["dispute_id"] == "SD-0001"
    assert request.payload["lane_1_record"] == two_lane_disagreement[0].model_dump(mode="json")
    assert request.payload["lane_2_record"] == two_lane_disagreement[1].model_dump(mode="json")
    assert "unrelated finding" not in canonical_json_bytes(request).decode()
```

- [ ] **Step 3: Run the request RED**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_requests.py -q
```

Expected: collection fails because `attorney_readiness_requests` does not exist.

- [ ] **Step 4: Implement baseline-locked grade packet construction**

Project `BaselineRequirementV1` into a grade subject without dropping definition-bound importance metadata. Ordinary response payloads use the exact `RequirementGradeV2` disposition/report-passage/rationale/omission semantics. Contested response payloads grade both reviewer and auditor alternatives and return the exact v2.2 ambiguity disposition inventory. Controller batches cover every ordinary requirement exactly once per lane in canonical order; contested requests cover every contested ID exactly once per lane.

- [ ] **Step 5: Implement controller-owned gap/safety inventories and fingerprints**

Use only verified objects from Task 2. Candidate identity is a canonical hash of `origin`, `subject_id`, both lane dispositions, baseline/report fingerprints, and controller evidence handles; it never includes evaluator-authored rationale. `build_safety_disputes_v1()` creates `SD-####` records for finding-existence, rationale, evidence-binding, visibility, blocker, follow-up, owner, or resolution-test differences. Byte-identical lane records create no dispute.

The lane schema requires exactly one `SafetyGapAssessmentV1` for every `GC-####`, plus zero or more bounded `SafetyFindingProposalV1` values for these report-wide classes:

```python
SafetyFindingKindV1 = Literal[
    "MATERIAL_UNSUPPORTED_ASSERTION",
    "BASELINE_CONTRADICTION",
    "HIDDEN_OR_UNDERSTATED_LIMITATION",
    "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
    "MISLEADING_CURRENTNESS_OR_AUTHORITY",
    "UNDISCLOSED_GRADER_GAP",
]
```

The compiler-contract fingerprint hashes all grade/safety request JSON schemas, rubric bytes, evidence-handle grammar, generic-refusal algorithm version, and canonicalization version. The separate strict-equivalent scoring fingerprint hashes the exact retained v2.2 importance weights, critical/coverage floors, uncertain-first rule, lane-disagreement rule, reason codes, and contested-alternative sensitivity algorithm. Full tests compare this descriptor against `RUBRIC_V22` and retained v2.2 scoring vectors without changing or importing a private helper as replay authority.

- [ ] **Step 6: Verify packet blindness and stability**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_requests.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_requests.py tests/evaluation/test_attorney_readiness_requests.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_requests.py
```

Expected: all pass; snapshot tests prove historical dispositions, report labels, candidate/generation metadata, and provider secrets are absent from fresh role packets, while stable-baseline/source/report bytes required for grading and safety review remain exact and private.

- [ ] **Step 7: Commit request construction**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_requests.py tests/evaluation/test_attorney_readiness_requests.py
git commit -m "feat: issue readiness safety packets"
```

---

### Task 4: Bounded Fresh-Grade and Safety Draft Compiler

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_drafts.py`
- Create: `tests/evaluation/test_attorney_readiness_drafts.py`

**Interfaces:**
- Consumes: Task 3 ordinary-grade, contested-grade, safety-lane, and safety-referee request packets; evaluator-authored bounded drafts; and `EvaluatorProvenanceV22`-equivalent provider/model/isolation metadata.
- Produces: `ReadinessEvaluatorDraftPromptV1`, `ReadinessEvaluatorProvenanceV1`, `ReadinessDraftReasonCodeV1`, `CompiledReadinessDraftV1`, `NeedsReadinessClarificationV1`, `ReadinessEngineDefectV1`, `ReadinessDraftCompileOutcomeV1`, and:

```python
def compile_readiness_draft_v1(
    request: ReadinessEvaluatorRequestV1,
    draft: object,
    provenance: ReadinessEvaluatorProvenanceV1,
) -> ReadinessDraftCompileOutcomeV1: ...
```

- [ ] **Step 1: Write generic/evidence/rationale RED tests**

Cover all four operation classes, native strict scalars, exact grade batch/candidate/dispute coverage, exact report-passage allowlist resolution, exact source/baseline evidence handles, duplicate removal, ambiguity refusal, unknown references, nonidentical conflicts, cycles, depth/byte/node bounds, and no Unicode/case/punctuation quote mutation. Ordinary grade drafts must cover every issued requirement ID once in order; contested drafts must grade both alternatives and bind the issued contested ID. Neither grade operation may return a strict disposition, score, readiness tier, gap ID, or historical v2.2 conclusion.

Mutation-test every rationale component independently. Deleting or genericizing `shortfall_description`, `why_unresolved`, `why_it_matters`, or `resolution_test`; repeating a disposition/reason code; supplying only a score; or asserting materiality without a scoped consequence must return clarification on attempt one and leave the request pending on attempt two.

```python
@pytest.mark.parametrize(
    "generic",
    [
        "more research needed",
        "More research is needed.",
        "insufficient information",
        "requirement partially met",
        "partially_met",
        "0.5",
    ],
)
def test_generic_why_unresolved_is_refused(request, generic) -> None:
    draft = valid_lane_draft(why_unresolved=generic)
    outcome = compile_readiness_draft_v1(request, draft, provenance())
    assert outcome == NeedsReadinessClarificationV1(
        (ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,)
    )
```

- [ ] **Step 2: Run the compiler RED**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_drafts.py -q
```

Expected: collection fails because `attorney_readiness_drafts` does not exist.

- [ ] **Step 3: Implement bounded draft and outcome types**

Use this discriminated result shape:

```python
@dataclass(frozen=True)
class CompiledReadinessDraftV1:
    response: ReadinessEvaluatorResponseV1
    normalization_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class NeedsReadinessClarificationV1:
    reason_codes: tuple[ReadinessDraftReasonCodeV1, ...]


@dataclass(frozen=True)
class ReadinessEngineDefectV1:
    reason_code: Literal[
        "READINESS_COMPILER_INVARIANT",
        "READINESS_COMPILER_PREFLIGHT_DISAGREEMENT",
    ]


ReadinessDraftCompileOutcomeV1 = (
    CompiledReadinessDraftV1
    | NeedsReadinessClarificationV1
    | ReadinessEngineDefectV1
)
```

Drafts may author substantive strings and request-local refs only. They never author `gap_id`, canonical order, conservative disposition, fingerprint, final blocker precedence, readiness tier, baseline-locked strict-equivalent disposition, or historical v2.2 disposition.

- [ ] **Step 4: Implement deterministic rationale validation**

Normalize only for generic-phrase detection by case-folding, Unicode normalization, punctuation removal, and whitespace collapse; preserve original accepted text bytes in the response. Require:

- `why_unresolved` to differ from disposition, reason code, and shortfall label;
- `why_it_matters` to name one fixed consequence kind (`legal_conclusion`, `applicability`, `implementation_decision`, `deadline`, `enforcement_exposure`, `attorney_follow_up`) and at least one controller evidence ref;
- `resolution_test` to name an observable evidence, fact, legal-judgment, or report-correction outcome;
- report-content findings to use exact allowlisted report passages;
- source/currentness/language assertions to bind exact source or prerequisite evidence handles; and
- critical gaps to use `prominent` visibility and `reviewing_attorney` or `outside_counsel` ownership.

For grade drafts, reuse the exact Protocol 2.2 report-passage, omission, disposition, contested-alternative, batch-coverage, and evidence-binding semantics against the typed stable-baseline projection. For safety/gap drafts, apply the rationale rules above. When evidence cannot support specificity, return `RATIONALE_EVIDENCE_UNBOUND`; never synthesize replacement prose.

- [ ] **Step 5: Verify the compiler**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_drafts.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_drafts.py tests/evaluation/test_attorney_readiness_drafts.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_drafts.py
```

Expected: all pass.

- [ ] **Step 6: Commit safe draft compilation**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_drafts.py tests/evaluation/test_attorney_readiness_drafts.py
git commit -m "feat: compile evidence grounded gap rationales"
```

---

### Task 5: Fresh Strict-Equivalent Scoring, Conservative Matrix, and Readiness Compiler

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_compiler.py`
- Create: `tests/evaluation/test_attorney_readiness_compiler.py`

**Interfaces:**
- Consumes: verified inputs, all accepted fresh grade fragments from both lanes, controller gap candidates, two accepted safety lane responses, zero or more accepted safety referee decisions, and the exact Task 1 rubric/scoring contract.
- Produces:

```python
def aggregate_baseline_locked_grader_lane_v1(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: Literal[1, 2],
    ordinary_fragments: tuple[BaselineLockedGradeFragmentV1, ...],
    contested_grades: tuple[BaselineLockedContestedGradeV1, ...],
) -> BaselineLockedGraderAggregateV1: ...


def derive_baseline_locked_strict_equivalent_v1(
    baseline: GradeableBaselineProjectionV1,
    lane_1: BaselineLockedGraderAggregateV1,
    lane_2: BaselineLockedGraderAggregateV1,
    rubric: ReadinessRubricV1,
) -> BaselineLockedStrictEquivalentV1: ...


def reconcile_safety_lanes_v1(
    inputs: VerifiedReadinessInputsV1,
    candidates: tuple[SafetyGapCandidateV1, ...],
    lane_1: SafetyLaneResponseV1,
    lane_2: SafetyLaneResponseV1,
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...],
) -> ReconciledSafetyReviewV1: ...


def compile_requirement_matrix_v1(
    inputs: VerifiedReadinessInputsV1,
    grader_lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
) -> RequirementMatrixV1: ...


def compile_gap_follow_up_matrix_v1(
    inputs: VerifiedReadinessInputsV1,
    strict_equivalent: BaselineLockedStrictEquivalentV1,
    candidates: tuple[SafetyGapCandidateV1, ...],
    safety: ReconciledSafetyReviewV1,
) -> GapFollowUpMatrixV1: ...


def derive_delivery_readiness_v1(
    inputs: VerifiedReadinessInputsV1,
    strict_equivalent: BaselineLockedStrictEquivalentV1,
    requirement_matrix: RequirementMatrixV1,
    gap_matrix: GapFollowUpMatrixV1,
    safety: ReconciledSafetyReviewV1,
) -> DeliveryReadinessResultV1: ...
```

- [ ] **Step 1: Write score and tier RED tests**

Test exact `0.699999...` fail, exact `0.70` pass, exact `0.90` high-assurance floor, worst-lane reconciliation, both-lane critical recall, critical partial/missing, material missing, uncertainty, fresh strict-equivalent `FAIL` review-ready, substantive strict-equivalent `INCONCLUSIVE` review-ready, strict-equivalent `PASS` review-ready due to a visible gap, and strict-equivalent `PASS` high assurance. Use integer numerator/denominator accumulation and compare exact rational products before converting display floats.

```python
def test_exact_seventy_percent_fail_can_be_review_ready(compilation_case) -> None:
    result = compilation_case(
        baseline_locked_strict_equivalent_disposition="FAIL",
        lane_credits=((7, 10), (8, 10)),
        visible_actionable_gaps=True,
        blocking_findings=(),
    )
    assert result.minimum_lane_weighted_coverage == 0.70
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"
    assert result.baseline_locked_strict_equivalent_disposition == "FAIL"


def test_one_lane_below_floor_fails_closed(compilation_case) -> None:
    result = compilation_case(lane_credits=((699, 1000), (1, 1)))
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MINIMUM_LANE_COVERAGE_BELOW_FLOOR" in result.blocking_codes
```

- [ ] **Step 2: Write retained-v2.2 scoring-equivalence and historical-isolation RED tests**

Use retained Protocol 2.2 public scoring vectors as expectations: any `uncertain` yields `INCONCLUSIVE/GRADE_UNCERTAIN`; otherwise exact importance-weighted `1.0/0.5/0.0` credit drives critical recall `1.0` and weighted coverage `0.90`; differing lane outcomes yield `INCONCLUSIVE/GRADER_DISAGREEMENT`; and contested reviewer/auditor worlds reproduce `OUTCOME_SENSITIVE_BASELINE_DISPUTE` and `BASELINE_EVIDENCE_INSUFFICIENT`. Assert the new scoring-contract fingerprint matches the packaged descriptor and retained vectors.

Parameterize optional historical dispositions `None/PASS/FAIL/INCONCLUSIVE` against every fresh disposition. Fresh aggregates, strict-equivalent result, matrices, tier, blockers, and handoff body must not change; only the separately labeled historical cross-check fields may differ.

```python
def test_historical_result_cannot_seed_or_override_fresh_grades(compilation_case) -> None:
    without = compilation_case(historical_v22=None, fresh_lane_outcomes=("PASS", "PASS"))
    with_fail = compilation_case(historical_v22="FAIL", fresh_lane_outcomes=("PASS", "PASS"))
    assert without.baseline_locked_strict_equivalent == with_fail.baseline_locked_strict_equivalent
    assert without.delivery_readiness == with_fail.delivery_readiness
    assert with_fail.historical_v22_strict_disposition == "FAIL"
```

- [ ] **Step 3: Write matrix/blocker RED tests**

Require rows for every origin; stable ordering by origin priority, baseline canonical order, subject ID, finding kind, and fingerprint; contiguous `GAP-####`; exact report passages; deterministic follow-up; and one row per safety finding. Mutation-test hidden gaps, unsupported assertions, contradictions, client-fact dependencies, misleading currentness/authority/language, missing follow-up, missing rationale component, generic rationale, evidence swap, false `resolved`, missing critical prominent disclosure, unsafe owner, completeness claim contradicting matrix, and outcome-determinative contest.

Assert blocker precedence is stable and independent of input order:

```python
assert result.blocking_codes == (
    "INTEGRITY_OR_PROVENANCE_INVALID",
    "MATERIAL_UNSUPPORTED_ASSERTION",
    "HIDDEN_MATERIAL_GAP",
    "GAP_RATIONALE_INVALID",
)
```

- [ ] **Step 4: Run compiler RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_compiler.py -q
```

Expected: collection fails because `attorney_readiness_compiler` does not exist.

- [ ] **Step 5: Aggregate fresh lanes and implement exact retained-v2.2 strict semantics**

Validate exact batch/contested inventory coverage, report/baseline/scoring-contract bindings, lane identity, and fragment fingerprints. Derive `BaselineLockedStrictEquivalentV1` in retained Protocol 2.2 order: lane uncertainty; per-lane critical/weighted floors; lane-outcome disagreement; contested-alternative sensitivity. Preserve exact retained reason codes and both lane aggregates, but serialize `protocol_version="delivery-readiness-v1"` and `semantics="attorney-eval-v2.2-strict-equivalent"`; never instantiate `EvaluationResultV22`.

- [ ] **Step 6: Implement exact review-ready scoring and requirement matrix**

For each fresh grader lane, score every stable-baseline requirement once with packaged importance weight and disposition credit. Compute:

```python
weighted_numerator = sum(importance_weight * disposition_half_units for each_grade)
weighted_denominator = 2 * sum(importance_weight for each_requirement)
weighted_coverage = weighted_numerator / weighted_denominator
critical_recall = critical_met_count / critical_requirement_count
```

Here half-units are `met=2`, `partially_met=1`, `not_met=0`, `uncertain=0`. Compare `10 * numerator >= 7 * denominator` for `0.70` and `10 * numerator >= 9 * denominator` for `0.90`; never use tolerance or rounded display values. Preserve both raw lane dispositions and compute the conservative one with the fixed severity order.

- [ ] **Step 7: Implement safety reconciliation and complete gap compilation**

Reject missing/extra lane assessments. A lane disagreement requires exactly one matching referee decision; an omitted, extra, duplicated, or mismatched referee decision is blocking and cannot be healed by controller preference. A blocking finding in either lane is provisionally blocking and remains so unless the fresh referee rejects that exact finding with evidence-bound reasoning; unresolved referee outcomes remain blocking. Controller-issue safety finding IDs only after reconciliation, then create one row per candidate/finding. Set first-version row status to `open`; evaluator drafts cannot claim resolution. A report-only future run may omit a genuinely corrected row based on fresh evidence, but no current row may be marked resolved without a separate versioned correction contract.

- [ ] **Step 8: Implement fail-closed tier derivation**

Evaluate in this order:

1. If any integrity/provenance/storage/replay/qualification/generation/baseline/parity-contract check is false, return `NOT_DELIVERABLE`.
2. If any substantive blocker exists, including a missing/generic/evidence-unbound rationale, return `NOT_DELIVERABLE`.
3. If the minimum lane coverage is below exact `0.70`, return `NOT_DELIVERABLE`.
4. If the fresh baseline-locked strict-equivalent disposition is `PASS`, both fresh lanes meet `1.0` critical recall and `0.90` weighted coverage, deterministic validation is completed with all three booleans true, all quality checks are true, and no blocking baseline/contest/safety finding exists, return `HIGH_ASSURANCE`.
5. If every gap is visible/actionable, critical disclosure/ownership is safe, no report completeness claim contradicts the matrix, and no blocker exists, return `REVIEW_READY_WITH_GAPS` even when the fresh strict-equivalent disposition is `FAIL` or substantive `INCONCLUSIVE`.
6. Otherwise return `NOT_DELIVERABLE` with allowlisted blocker codes.

Do not read optional historical Protocol 2.2 evidence in this branch. After the tier is fixed, attach `historical_v22_strict_disposition` and `NOT_PROVIDED`, `BASELINE_NOT_COMPARABLE`, `REPORT_NOT_COMPARABLE`, `MATCH`, or `DISPOSITION_DIFFERS` for transparency only.

The per-run `parity_contract_valid` check means full and portable engines loaded the same packaged policy/compiler fingerprints. Exact full/portable complete-tree equality remains a mandatory external gate in Tasks 10-12; the compiler must not fabricate a case-specific parity receipt.

- [ ] **Step 9: Verify compiler and mutation sensitivity**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_compiler.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_compiler.py tests/evaluation/test_attorney_readiness_compiler.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_compiler.py
```

Expected: all pass, including a parameterized mutation test proving every threshold and blocker changes at least one expected tier.

- [ ] **Step 10: Commit deterministic compilation**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_compiler.py tests/evaluation/test_attorney_readiness_compiler.py
git commit -m "feat: derive conservative delivery readiness"
```

---

### Task 6: Deterministic Attorney Handoff and Nondelivery Suppression

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_handoff.py`
- Create: `tests/evaluation/test_attorney_readiness_handoff.py`

**Interfaces:**
- Consumes: exact report text, `RequirementMatrixV1`, `GapFollowUpMatrixV1`, `DeliveryReadinessResultV1`, and rubric warning bytes.
- Produces:

```python
def render_attorney_review_handoff_v1(
    *,
    report_text: str,
    requirement_matrix: RequirementMatrixV1,
    gap_matrix: GapFollowUpMatrixV1,
    result: DeliveryReadinessResultV1,
) -> bytes: ...
```

- [ ] **Step 1: Write all-tier Markdown RED tests**

For `HIGH_ASSURANCE`, require readiness label, separate `Baseline-locked strict-equivalent disposition`, optional `Historical Protocol 2.2 strict disposition` shown only when supplied, report, full requirement matrix, complete gap matrix, and warning. For `REVIEW_READY_WITH_GAPS`, additionally require a prominent label and prioritized attorney/outside-counsel follow-up list. Render every row under exact headings `What is missing`, `Why it matters`, `How to resolve it`, and `Owner`. A historical mismatch is disclosed as cross-check context and never changes the tier or follow-up priority.

For `NOT_DELIVERABLE`, assert the report, report excerpts, requirement matrix, gap rationale, source text, provider/model metadata, commands, run paths, hidden labels, and role mechanics are absent; only status, allowlisted blocker codes, operator-safe remediation classes, and the warning remain.

```python
def test_nondeliverable_handoff_suppresses_work_product(blocked_case) -> None:
    rendered = render_attorney_review_handoff_v1(**blocked_case).decode()
    assert "NOT_DELIVERABLE" in rendered
    assert blocked_case["report_text"] not in rendered
    assert "eval-readiness-submit-safe" not in rendered
    assert "anonymous_label" not in rendered
    assert "/Users/" not in rendered
```

- [ ] **Step 2: Run handoff RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_handoff.py -q
```

Expected: collection fails because `attorney_readiness_handoff` does not exist.

- [ ] **Step 3: Implement byte-stable rendering**

Use a fixed heading order, LF newlines, no timestamp, no environment-dependent wrapping, escaped Markdown cell content, canonical matrix order, and packaged warning copy. Prioritize follow-ups by critical before material before supporting, then `outside_counsel`, `reviewing_attorney`, `research_operator`, then row order. Group display actions by `(follow_up_code, owner_role)` but list every contributing `GAP-####` so no row disappears.

- [ ] **Step 4: Verify privacy, content, and determinism**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_handoff.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_handoff.py tests/evaluation/test_attorney_readiness_handoff.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_handoff.py
```

Expected: all pass; repeated renders and permuted input maps are byte-identical.

- [ ] **Step 5: Commit the attorney handoff**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_handoff.py tests/evaluation/test_attorney_readiness_handoff.py
git commit -m "feat: render safe attorney readiness handoff"
```

---

### Task 7: Immutable Readiness Graph and Exact Replay

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py`
- Create: `tests/evaluation/test_attorney_readiness_artifacts.py`

**Interfaces:**
- Consumes: all strict contracts and deterministic builders from Tasks 1-6 plus existing `open_evaluation_storage()`/artifact-record patterns.
- Produces: `ReadinessResponsePreflightV1`, `VerifiedReadinessContextV1`, `initialize_readiness_run_storage_v1()`, `commit_readiness_transition_v1()`, `preflight_readiness_response_v1()`, `verify_readiness_run_v1()`, `load_verified_readiness_run_v1()`, and `load_verified_readiness_context_v1()`.

Canonical terminal inventory:

```text
readiness-manifest.json
readiness-input.json
readiness-rubric.json
requests/grade-lane-1-GB-1-####.json
responses/grade-lane-1-GB-1-####.json
requests/grade-lane-2-GB-2-####.json
responses/grade-lane-2-GB-2-####.json
requests/contested-grade-lane-1-CT-####.json       # zero or more
responses/contested-grade-lane-1-CT-####.json      # zero or more
requests/contested-grade-lane-2-CT-####.json       # zero or more
responses/contested-grade-lane-2-CT-####.json      # zero or more
aggregates/grader-lane-1.json
aggregates/grader-lane-2.json
baseline-locked-strict-equivalent.json
historical-v22-cross-check.json                    # only when supplied
requests/safety-lane-1.json
responses/safety-lane-1.json
requests/safety-lane-2.json
responses/safety-lane-2.json
requests/safety-referee-SD-####.json          # zero or more
responses/safety-referee-SD-####.json         # zero or more
aggregates/safety-review.json
requirement-matrix.json
gap-follow-up-matrix.json
delivery-readiness.json
attorney-review-handoff.md
readiness-verification.json
```

- [ ] **Step 1: Write replay/inventory RED tests**

Test every partial lifecycle state across fresh grade fragments, contested grades, safety lanes, and safety referees; exactly zero or one pending call; append-only accepted responses; deterministic terminal inventory; replay-derived grader aggregates/strict-equivalent result/matrices/Markdown; and terminal `HIGH_ASSURANCE`, `REVIEW_READY_WITH_GAPS`, and `NOT_DELIVERABLE`. Assert there is no path inside any Protocol 2.2 or baseline run after readiness initialization, and a report revision can complete with no Protocol 2.2 run at all.

Mutation tests must reject missing/extra/orphan artifacts, duplicate JSON keys, oversized artifacts, tamper-and-reseal of inputs/grade or safety requests/responses/grader or safety aggregates/strict-equivalent result/matrices/final result/handoff/verification/manifest, cross-run swaps, report swaps, grade-target swaps, baseline swaps, qualification/generation/capsule swaps, call reorder/skip/duplicate, grader/safety lane swaps, favorable referee substitution, rubric/scoring-contract drift, and retained-root changes. Changing optional historical evidence may change only its cross-check artifact and bound downstream display bytes, never fresh grades or tier.

- [ ] **Step 2: Run artifact RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_artifacts.py -q
```

Expected: collection fails because `attorney_readiness_artifacts` does not exist.

- [ ] **Step 3: Implement manifest/inventory replay grammar**

Use these public signatures:

```python
def verify_readiness_run_v1(run_dir: Path) -> ReadinessVerificationV1: ...


def load_verified_readiness_run_v1(
    run_dir: Path,
) -> tuple[ReadinessManifestV1, DeliveryReadinessResultV1 | None]: ...


def load_verified_readiness_context_v1(
    run_dir: Path,
) -> VerifiedReadinessContextV1: ...
```

Replay must reconstruct every fresh grade and safety request from `readiness-input.json`, the verified gradeable-baseline projection, rubric/scoring-contract bytes, prior accepted responses, and controller rules; recompile both grader aggregates, strict-equivalent result, safety aggregate, matrices, tier, and handoff; compare exact bytes; and verify the exact relative inventory and artifact hashes. `readiness-verification.json` binds a deterministic pre-manifest graph fingerprint and allowlisted check booleans; the terminal manifest binds its exact bytes without a circular manifest-root reference.

- [ ] **Step 4: Reuse hardened storage without weakening it**

Create readiness-specific wrappers over the existing descriptor-anchored storage rather than path-based reads/writes. Keep no-follow, regular-file, link-count, ownership, root-identity, atomic no-replace, fsync, rollback, and post-commit verification semantics. A failed preflight or rejected response is byte-for-byte write-free. An integrity/storage failure raises an allowlisted readiness integrity code and never emits a readiness result.

- [ ] **Step 5: Add race and rollback tests**

Cover concurrent submit/status/verify, alias paths to one inode, root replacement before/during commit, inherited artifact replacement, destination competitor, rollback before/after manifest replacement, FIFO/symlink/hard-link/device nodes, and injected crash after every durable boundary. Compare tree bytes before and after each refused mutation.

- [ ] **Step 6: Verify artifacts and security**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_artifacts.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py tests/evaluation/test_attorney_readiness_artifacts.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py
```

Expected: all pass.

- [ ] **Step 7: Commit the immutable graph**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_artifacts.py tests/evaluation/test_attorney_readiness_artifacts.py
git commit -m "feat: seal and replay readiness companions"
```

---
### Task 8: Resumable Fresh Grading and Safety Workflow

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_readiness_workflow.py`
- Create: `tests/evaluation/test_attorney_readiness_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: Tasks 1-7 and an internal adapter implementing `ReadinessDraftEvaluatorV1`.
- Produces: `ReadinessDraftEvaluatorV1`, `ReadinessTelemetryEventV1`, `ReadinessDriverOutcomeV1`, `GuardedReadinessSubmissionResultV1`, and:

```python
def initialize_readiness_v1(
    output_dir: Path,
    *,
    baseline_run_dir: Path,
    qualification_run_dir: Path,
    generation_run_dir: Path,
    validation_receipt_path: Path,
    historical_v22_run_dir: Path | None = None,
    historical_anonymous_label: Literal["A", "B"] | None = None,
) -> ReadinessRunStateV1: ...


def next_readiness_request_v1(run_dir: Path) -> ReadinessEvaluatorRequestV1 | None: ...
def resume_readiness_v1(run_dir: Path) -> ReadinessRunStateV1: ...
def preflight_readiness_response_v1(run_dir: Path, response: object) -> ReadinessResponsePreflightV1: ...
def guarded_submit_readiness_response_v1(
    run_dir: Path, response: object
) -> GuardedReadinessSubmissionResultV1: ...
def submit_readiness_response_v1(run_dir: Path, response: object) -> ReadinessRunStateV1: ...


async def continue_readiness_v1(
    run_dir: Path,
    evaluator: ReadinessDraftEvaluatorV1,
    *,
    telemetry_sink: ReadinessTelemetrySinkV1 | None = None,
) -> ReadinessDriverOutcomeV1: ...
```

- [ ] **Step 1: Write lifecycle RED tests**

Assert exact operation order: every ordinary and contested grade request for fresh lane 1; every ordinary and contested grade request for fresh lane 2; aggregate and derive strict-equivalent result; safety lane 1; safety lane 2; each controller-sorted safety-referee dispute; compile; terminal. Grade lane 2 is built without lane 1 response bytes; safety lane 2 is built without safety lane 1 response bytes; every grade fragment, contested grade, safety lane, safety referee, and repair uses a genuinely fresh evaluator prompt. Accepted requests are never reissued after resume or crash.

Cover fresh strict-equivalent `PASS`, `FAIL`, and substantive `INCONCLUSIVE`; all three readiness tiers; report revision with no historical Protocol 2.2 run; matching/differing/noncomparable historical cross-checks; no-dispute and multi-dispute paths; process interruption after every accepted grade/safety role; stale concurrent submission; wrong request fingerprint; wrong lane/batch/contested/dispute identity; terminal submission; and exact resume.

```python
async def test_second_mechanical_refusal_pauses_without_nondelivery(
    initialized_run, refusing_evaluator
) -> None:
    before = tree_bytes(initialized_run)
    outcome = await continue_readiness_v1(initialized_run, refusing_evaluator)
    assert outcome.engine_paused is True
    assert outcome.exit_code == 6
    assert outcome.result is None
    assert next_readiness_request_v1(initialized_run) == outcome.pending_request
    assert "delivery-readiness.json" not in tree_bytes(initialized_run)
    assert before.items() <= tree_bytes(initialized_run).items()
```

- [ ] **Step 2: Run workflow RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_workflow.py -q
```

Expected: collection fails because `attorney_readiness_workflow` does not exist.

- [ ] **Step 3: Implement initialization and external guarded lifecycle**

Initialization runs Task 2 admission before creating `output_dir`, snapshots only sanitized/canonical inputs, and issues the first fresh grade fragment for lane 1. Every submit occurs under the existing inode-derived submission lock and Task 7 preflight/commit boundary. After both grader lanes, derive the strict-equivalent result and gap candidates, then issue both safety lanes. After safety lane 2, build the exact safety-dispute inventory; after the last referee, compile and atomically install terminal derived artifacts.

Return exact exit behavior from terminal verified state:

```python
def readiness_exit_code_v1(result: DeliveryReadinessResultV1 | None, *, paused: bool) -> int:
    if paused:
        return 6
    if result is None:
        return 3
    if result.delivery_readiness is DeliveryReadinessTierV1.NOT_DELIVERABLE:
        return 4
    return 0
```

Integrity/unsupported secure-storage exceptions remain exit `5` at the CLI boundary, not readiness results.

- [ ] **Step 4: Implement the internal two-attempt driver**

`ReadinessDraftEvaluatorV1` has one method:

```python
@runtime_checkable
class ReadinessDraftEvaluatorV1(Protocol):
    async def evaluate_draft(self, prompt: ReadinessEvaluatorDraftPromptV1) -> object: ...
```

For each exact pending grade or safety request, create attempt 1 with no clarification codes. On `NeedsReadinessClarificationV1`, issue attempt 2 in a fresh context with only allowlisted reason codes, never rejected bytes. A second refusal returns a pause outcome with the original request still pending. Unfavorable grades and safety findings are substantive and are accepted/replayed; never retry either to obtain a better strict-equivalent disposition or tier.

- [ ] **Step 5: Add public-safe telemetry and freshness assertions**

Telemetry may contain protocol/compiler/scoring fingerprints, operation, grader-or-safety lane, batch/contested/dispute class, attempt, normalization/clarification codes, pause/resume counts, and no private text/paths/historical disposition/report labels. Tests must instantiate a new evaluator context token for every grade fragment, contested grade, safety lane, referee, and repair and reject adapter reuse that claims `judge_isolation != "fresh_context"` outside scripted fixtures.

- [ ] **Step 6: Verify workflow**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_workflow.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_readiness_workflow.py tests/evaluation/test_attorney_readiness_workflow.py src/regulatory_harvest/evaluation/__init__.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_readiness_workflow.py
```

Expected: all pass.

- [ ] **Step 7: Commit workflow orchestration**

```bash
git add src/regulatory_harvest/evaluation/attorney_readiness_workflow.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_readiness_workflow.py
git commit -m "feat: run resumable readiness safety review"
```

---

### Task 9: Full CLI Command Family and Stable Public Output

**Files:**
- Modify: `scripts/attorney_eval_full.py`
- Create: `tests/cli/test_readiness_cli.py`
- Modify: `tests/cli/test_eval_cli.py`

**Interfaces:**
- Consumes: Task 8 public workflow API and existing exit constants `0`, `2`, `3`, `4`, `5`, `6`.
- Produces five separate commands:

```text
eval-readiness-init
eval-readiness-next
eval-readiness-submit-safe
eval-readiness-status
eval-readiness-verify
```

- [ ] **Step 1: Write parser/help/compatibility RED tests**

Lock these command arguments:

```text
eval-readiness-init --baseline-run PATH --qualification-run PATH --generation-run PATH --validation-receipt PATH --run PATH [--historical-v22-run PATH --historical-report-label {A,B}]
eval-readiness-next --run PATH
eval-readiness-submit-safe --run PATH --response PATH [--provider-name NAME --model-name NAME --judge-isolation fresh_context|scripted_fixture]
eval-readiness-status --run PATH
eval-readiness-verify --run PATH
```

Snapshot every legacy command's `--help`, JSON output, default protocol, and exit code before adding parsers, then assert snapshots stay byte-identical. In particular, `eval-init` retains `choices=("2.1", "2.2")` and `default="2.1"`; no readiness option appears in retained command payloads.

- [ ] **Step 2: Run CLI RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/cli/test_readiness_cli.py tests/cli/test_eval_cli.py -q
```

Expected: readiness parser tests fail with `invalid choice: 'eval-readiness-init'`; retained tests continue to pass.

- [ ] **Step 3: Add exact JSON status and verification payloads**

`eval-readiness-status` returns only allowlisted metadata:

```json
{
  "delivery_readiness": "REVIEW_READY_WITH_GAPS",
  "engine_paused": false,
  "manifest_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "pending_operation": null,
  "protocol_version": "delivery-readiness-v1",
  "baseline_locked_strict_equivalent_disposition": "PASS",
  "historical_v22_cross_check_status": "DISPOSITION_DIFFERS",
  "historical_v22_strict_disposition": "FAIL"
}
```

The concrete output uses the run's real 64-hex fingerprint; the repeated `a` value is a valid synthetic fixture digest. Pending status sets the fresh strict-equivalent and readiness fields to `null`, retains only already-bound historical cross-check metadata, exposes only operation/lane/batch/contested/dispute class, and exits `0`; an engine pause exits `6`. Verification returns `ok`, manifest/root/result/scoring fingerprints, fresh strict-equivalent disposition, optional historical v2.2 disposition/cross-check status, delivery readiness, and allowlisted issue codes only. Human output prints `Baseline-locked strict-equivalent: PASS`, `Historical Protocol 2.2 strict disposition: FAIL (cross-check differs)`, and `Delivery readiness: REVIEW_READY_WITH_GAPS` on separate lines; when no history is supplied it prints `Historical Protocol 2.2 strict disposition: not supplied`.

- [ ] **Step 4: Implement command dispatch and exit codes**

Initialization/input errors—including supplying only one historical option—exit `2` without creating a run. Fresh verified substantive strict-equivalent/readiness inconclusive without a safe tier exits `3`. Verified `NOT_DELIVERABLE` exits `4`. Integrity or unsupported secure storage exits `5`. Verified pause exits `6`. Verified `HIGH_ASSURANCE` and `REVIEW_READY_WITH_GAPS` exit `0`; historical v2.2 disagreement never changes the exit.

`eval-readiness-submit-safe` reads bounded canonical JSON, translates optional provenance flags into a strict response envelope, and returns `accepted: false` with neutral diagnostics and no writes for mechanical invalidity. It never provides a command that mechanically terminalizes a pending role as `NOT_DELIVERABLE`.

- [ ] **Step 5: Verify full CLI and retained bytes**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/cli/test_readiness_cli.py tests/cli/test_eval_cli.py -q
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_v22_models.py tests/evaluation/test_attorney_v22_compiler.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_v22_workflow.py -q
.venv/bin/ruff check scripts/attorney_eval_full.py scripts/harvest_skill.py tests/cli/test_readiness_cli.py tests/cli/test_eval_cli.py
.venv/bin/mypy src
```

Expected: all pass, including byte snapshots for retained 1.3/2.0/2.1/2.2 commands.

- [ ] **Step 6: Commit full CLI support**

```bash
git add scripts/attorney_eval_full.py tests/cli/test_readiness_cli.py tests/cli/test_eval_cli.py
git commit -m "feat: expose readiness companion CLI"
```

---

### Task 10: Isolated-Portable Mirror and Exact Complete-Tree Parity

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Create: `tests/evaluation/test_attorney_readiness_stress.py`

**Interfaces:**
- Consumes: the Task 1 rubric file by path from the extracted package and the same five CLI contracts from Task 9.
- Produces: isolated `python -I -S` readiness lifecycle behavior with exact full/portable request, response, aggregate, matrix, result, manifest, Markdown, status, verification, exit, and complete-tree parity.

- [ ] **Step 1: Write portable RED tests before mirror code**

Run every `--help` command under isolated Python. Add terminal journeys for exact `0.70` review-ready fresh strict-equivalent `FAIL`, fresh strict-equivalent `PASS` high assurance, and blocked unsupported assertion; a revised report with no historical v2.2 run; matching/differing/noncomparable optional history; pause/resume during grading and safety; one safety dispute/referee; tamper verification; and retained protocol read-only behavior.

Compare complete trees, not selected outputs:

```python
def test_readiness_complete_tree_full_portable_parity(full_run, portable_run) -> None:
    assert tree_bytes(full_run) == tree_bytes(portable_run)
    assert command_json(FULL, "eval-readiness-status", full_run) == command_json(
        PORTABLE, "eval-readiness-status", portable_run, isolated=True
    )
    assert command_json(FULL, "eval-readiness-verify", full_run) == command_json(
        PORTABLE, "eval-readiness-verify", portable_run, isolated=True
    )
```

- [ ] **Step 2: Run portable RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/scripts/test_attorney_eval_portable.py -k readiness -q
```

Expected: tests fail because portable dispatch does not recognize the readiness command family.

- [ ] **Step 3: Mirror strict models, compiler, replay, workflow, and CLI**

Add one clearly bounded `delivery-readiness-v1 portable mirror` section. Mirror behavior without importing Pydantic or site packages. Consume the prerequisite baseline portable verifier/projection and prove its `GradeableBaselineProjectionV1` canonical bytes and `grade_target_fingerprint` equal the full projection before issuing a grade request. Load and duplicate-key-validate `src/regulatory_harvest/evaluation/readiness-rubric-v1.json` at runtime; compute its hash and require the same compiler and retained-v2.2-equivalent scoring fingerprints as full. Do not redeclare `0.70`, `0.90`, strict weights/semantics, rationale kinds, follow-up codes, owner roles, generic phrases, warning copy, or disposition credits in Python constants.

- [ ] **Step 4: Add deterministic stress matrix**

Generate at least 96 seeded public-synthetic cases spanning:

- requirement counts `0, 1, 5, 6, 52, 128, 129`;
- gap/finding counts `0, 1, 5, 6, 21, 129`;
- coverage just below/at/above `0.70` and `0.90`;
- every fresh strict-equivalent disposition, optional historical disposition/cross-check status, and readiness tier;
- every rationale kind, follow-up code, and owner role;
- lane agreement and each dispute kind;
- hidden/visible/prominent gaps and every blocker;
- normalization, one-repair success, second-refusal pause, interrupt/resume; and
- no historical Protocol 2.2 source plus optional one-report and two-report historical sources with both seed orientations.

Each seed runs full and portable independently and compares grade/safety transcript, request/response bytes, grader aggregates, strict-equivalent result, optional historical cross-check, complete tree, terminal status, fresh/historical/readiness dispositions, matrix count/order/fingerprints, Markdown bytes, verification root, and exit code.

- [ ] **Step 5: Verify portable parity and isolated operation**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/scripts/test_attorney_eval_portable.py -k 'readiness or retained' -q
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_stress.py -q
python -I -S scripts/harvest_portable.py eval-readiness-init --help
python -I -S scripts/harvest_portable.py eval-readiness-next --help
python -I -S scripts/harvest_portable.py eval-readiness-submit-safe --help
python -I -S scripts/harvest_portable.py eval-readiness-status --help
python -I -S scripts/harvest_portable.py eval-readiness-verify --help
.venv/bin/ruff check scripts/attorney_eval_portable.py scripts/harvest_portable.py tests/evaluation/test_attorney_readiness_stress.py tests/scripts/test_attorney_eval_portable.py
```

Expected: all pass; isolated help emits no import error and stress trees are byte-identical.

- [ ] **Step 6: Commit portable parity**

```bash
git add scripts/attorney_eval_portable.py tests/scripts/test_attorney_eval_portable.py tests/evaluation/test_attorney_readiness_stress.py
git commit -m "feat: mirror readiness in portable runtime"
```

---

### Task 11: Public Fixtures, Templates, Documentation, and Calibration Contract

**Files:**
- Create: `assets/attorney-delivery-readiness-input.template.json`
- Create: `assets/attorney-delivery-readiness-response.template.json`
- Create: `tests/fixtures/attorney-readiness-v1/FIXTURE_LICENSE.md`
- Create: `tests/fixtures/attorney-readiness-v1/stable/source.txt`
- Create: `tests/fixtures/attorney-readiness-v1/stable/report-high-assurance.md`
- Create: `tests/fixtures/attorney-readiness-v1/stable/report-review-ready.md`
- Create: `tests/fixtures/attorney-readiness-v1/stable/report-not-deliverable.md`
- Create: `tests/fixtures/attorney-readiness-v1/stable/validation-receipt.json`
- Create: `tests/fixtures/attorney-readiness-v1/stable/scripted-drafts.json`
- Create: `tests/fixtures/attorney-readiness-v1/calibration-record.template.json`
- Modify: `docs/evaluation.md`
- Modify: `README.md`
- Modify: `SKILL.md`
- Modify: `references/attorney-evaluation.md`
- Modify: `references/security-and-privacy.md`
- Modify: `docs/release-checklist.md`
- Modify: `tests/fixtures/FIXTURE_LICENSES.md`
- Modify: `tests/skill/test_skill_package.py`

**Interfaces:**
- Consumes: final full/portable CLI and public synthetic protocol contracts.
- Produces: licensed reproducible examples for all tiers, a nonprivate calibration schema, and operator/attorney guidance that never overstates readiness.

- [ ] **Step 1: Write documentation/template/fixture RED tests**

Assert the two templates validate against exact Task 1/3 schemas and contain no private path or matter data. Assert fixture license registration and all three deterministic expected tiers. Assert docs distinguish two fresh baseline-locked grading lanes, two fresh safety lanes/referee, the fresh strict-equivalent result, optional historical v2.2 cross-check, and readiness; they also include the exact `0.70` provisional floor, rationale headings, exit codes, no client-delivery authorization, Protocol 2.1 default, explicit baseline reuse, and mandatory warning.

Assert the calibration template has exact fields:

```json
{
  "attorney_usefulness": "useful|useful_with_changes|not_useful",
  "baseline_correction_required": false,
  "baseline_locked_strict_equivalent_disposition": "FAIL",
  "case_id": "public-synthetic-case-id",
  "delivery_readiness": "REVIEW_READY_WITH_GAPS",
  "fresh_grade_lane_weighted_coverage": [0.7, 0.8],
  "follow_up_sufficient": true,
  "gap_visibility_adequate": true,
  "historical_v22_cross_check_status": "NOT_PROVIDED",
  "historical_v22_strict_disposition": null,
  "importance_disagreement_count": 0,
  "readiness_rubric_version": "delivery-readiness-v1",
  "strict_equivalent_scoring_semantics": "attorney-eval-v2.2",
  "unsafe_delivery_observed": false
}
```

- [ ] **Step 2: Run docs/fixture RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/skill/test_skill_package.py -k 'readiness or warning or default_protocol' -q
```

Expected: tests fail because readiness templates, fixtures, and required documentation are absent.

- [ ] **Step 3: Add licensed synthetic tier fixtures**

Use one fictional rule with no real jurisdiction/client/matter identifiers. The high-assurance report must produce fresh strict-equivalent `PASS`, both grade-lane scores above thresholds, no blockers, and an empty or nonblocking complete gap matrix. The review-ready report must produce fresh strict-equivalent `FAIL`, exact minimum lane `0.70`, visible/actionable gaps, and no blocker. The nondeliverable report must include one material unsupported assertion and suppress report delivery. All three complete without historical Protocol 2.2 input; a separate vector attaches synthetic historical `FAIL` to fresh `PASS` and proves the tier is unchanged. Scripted drafts cover two grade lanes, two safety lanes, and a safety-referee dispute; fixture metadata states public-synthetic provenance and an Apache-2.0-compatible license.

- [ ] **Step 4: Document operator and attorney semantics**

Show one exact CLI lifecycle using the fixture paths, label the readiness graph as private work product, and state:

- fresh baseline-locked strict-equivalent `FAIL` remains `FAIL` even when review-ready;
- optional historical Protocol 2.2 disposition is separately labeled cross-check evidence and never supplies fresh grades or changes the tier;
- exit `0` for review-ready means intentional attorney-review delivery, not legal correctness;
- `NOT_DELIVERABLE` preserves sealed artifacts and returns only operator-safe remediation;
- a report revision reuses the same verified baseline only when `legal_input_fingerprint` is identical;
- legal-input changes require a new baseline;
- every fresh role must be isolated; and
- publication/default changes require separate review and authorization.

- [ ] **Step 5: Document the calibration gate without recording private results**

Require at least three, preferably five, diverse attorney-reviewed cases before changing `0.70`; for every report revision record fresh strict-equivalent disposition, both fresh grade-lane matrices/scores, tier, matrix visibility, usefulness, follow-up sufficiency, false nondelivery, unsafe delivery, importance disagreement, baseline correction rate, and optional historical v2.2 disposition/comparability/delta outside the public repository when cases are private. Threshold/blocker/scoring-contract changes require a new rubric version and may never weaken integrity, silently diverge from retained v2.2 semantics, or rewrite historical results.

- [ ] **Step 6: Verify content and fixtures**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/skill/test_skill_package.py -q
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_workflow.py tests/cli/test_readiness_cli.py -q
.venv/bin/ruff check tests/skill/test_skill_package.py
```

Expected: all pass.

- [ ] **Step 7: Commit fixtures and guidance**

```bash
git add assets/attorney-delivery-readiness-input.template.json assets/attorney-delivery-readiness-response.template.json tests/fixtures/attorney-readiness-v1 tests/fixtures/FIXTURE_LICENSES.md docs/evaluation.md README.md SKILL.md references/attorney-evaluation.md references/security-and-privacy.md docs/release-checklist.md tests/skill/test_skill_package.py
git commit -m "docs: publish readiness workflow contract"
```

---

### Task 12: Package Completeness, Retained Compatibility, and Release Gates

**Files:**
- Modify: `scripts/skill-package-files.txt`
- Modify: `scripts/build_skill.py`
- Modify: `scripts/audit_release.py`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/scripts/test_audit_release.py`
- Modify: `docs/release-checklist.md`

**Interfaces:**
- Consumes: all runtime/docs/assets from Tasks 1-11.
- Produces: deterministic source/wheel/skill packages containing the complete readiness workflow, plus explicit full/portable/package/compatibility/security gate evidence. This task does not publish anything.

- [ ] **Step 1: Write package-guard RED tests**

Extend `READINESS_ARCHIVE_REQUIREMENTS` in `scripts/build_skill.py` to require the rubric, both templates, all eight readiness runtime modules, docs/reference updates, and both full/portable runners. Parameterize removal of each required entry and assert `SkillBuildError` names the missing readiness input. Assert lexical, unique manifest order and wheel inclusion of `readiness-rubric-v1.json` through `importlib.resources` in an installed wheel. Extend the release audit's generated-artifact inventory with the readiness manifest/input, safety request/response, requirement/gap matrix, result, verification, and attorney-handoff filenames; tests must prove an accidentally tracked private readiness run or archived handoff is rejected with neutral codes and no matched content.

- [ ] **Step 2: Run package RED tests**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/scripts/test_build_skill.py -k readiness -q
```

Expected: tests fail because the package manifest/guard does not include readiness files.

- [ ] **Step 3: Add package entries and deterministic extracted lifecycle**

Add every new runtime/data/template/reference file to `scripts/skill-package-files.txt` in lexical order. Build the skill ZIP, extract it to a temporary directory, and run all five readiness `--help` commands plus the three fixture terminal journeys with the full runner and isolated portable runner. Assert one archive root, no tests/plans/Git/cache/generated run/private data, identical full/portable trees, and exact rubric bytes equal the source asset.

- [ ] **Step 4: Lock retained-protocol compatibility**

Run existing retained fixtures through both full and portable verifiers before and after the new commands. Hash every retained fixture tree and command transcript and assert no differences. Explicitly test:

```python
@pytest.mark.parametrize("protocol", ["1.3", "2.0", "2.1", "2.2"])
def test_readiness_packaging_does_not_change_retained_protocol_bytes(protocol) -> None:
    assert rebuilt_retained_tree(protocol) == frozen_retained_tree(protocol)
    assert retained_status_bytes(protocol) == frozen_status_bytes(protocol)
    assert retained_verify_exit(protocol) == frozen_verify_exit(protocol)
```

Also assert no historical run acquires an inferred readiness sibling; explicit readiness initialization is the only creation path.

- [ ] **Step 5: Run focused full/portable/package/compatibility/security gates**

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_readiness_models.py tests/evaluation/test_attorney_readiness_inputs.py tests/evaluation/test_attorney_readiness_requests.py tests/evaluation/test_attorney_readiness_drafts.py tests/evaluation/test_attorney_readiness_compiler.py tests/evaluation/test_attorney_readiness_handoff.py tests/evaluation/test_attorney_readiness_artifacts.py tests/evaluation/test_attorney_readiness_workflow.py tests/evaluation/test_attorney_readiness_stress.py -q
PYTHONPATH=src .venv/bin/pytest tests/evaluation/test_attorney_v22_models.py tests/evaluation/test_attorney_v22_compiler.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_v22_workflow.py tests/evaluation/test_attorney_v22_stress.py -q
PYTHONPATH=src .venv/bin/pytest tests/scripts/test_attorney_eval_portable.py tests/scripts/test_build_skill.py tests/scripts/test_audit_release.py tests/skill/test_skill_package.py -q
.venv/bin/ruff check .
.venv/bin/mypy src
```

Expected: all pass.

- [ ] **Step 6: Run the complete test/build gate**

Run:

```bash
uv sync --frozen --all-extras --dev
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
```

Expected: all tests pass, lint/type checks pass, and wheel/sdist build succeeds.

- [ ] **Step 7: Prove deterministic archives and exact audit target**

Run:

```bash
mkdir -p dist/readiness-repro-a dist/readiness-repro-b
python3 scripts/build_skill.py --output dist/readiness-repro-a/regulatory-harvest-skill.zip
python3 scripts/build_skill.py --output dist/readiness-repro-b/regulatory-harvest-skill.zip
cmp dist/readiness-repro-a/regulatory-harvest-skill.zip dist/readiness-repro-b/regulatory-harvest-skill.zip
shasum -a 256 dist/readiness-repro-a/regulatory-harvest-skill.zip dist/readiness-repro-b/regulatory-harvest-skill.zip
uv run python scripts/audit_release.py --repo . --archive dist/readiness-repro-a/regulatory-harvest-skill.zip --json
```

Expected: `cmp` exits `0`; SHA-256 values are identical; audit returns no automated finding and still reports `MANUAL_CONFIRMATION_REQUIRED`.

- [ ] **Step 8: Run reachable-history and privacy review without exposing matches**

Use the repository's approved external private-marker file only from its local access-controlled location; never add it to this repository or plan. Run the documented release audit with `--private-markers`, then inspect reachable objects and detached archive contents for credentials, private evaluation markers, home paths, generated work product, and unexpected binary/non-UTF-8 files. Record only neutral finding codes/counts and candidate commit/hash under an access-controlled private verification record. Any finding blocks release; do not add an allowlist merely to make this gate pass.

Expected: zero automated privacy/history findings. `MANUAL_CONFIRMATION_REQUIRED` remains because automated success is not publication authorization.

- [ ] **Step 9: Run the fresh private readiness gate only after public gates pass**

Outside the repository, initialize a new readiness companion directly against a reused verified stable baseline and revised generation capsule, without requiring a new Protocol 2.2 run. Use one isolated context per grade fragment, contested grade, safety lane, referee, and repair. Optionally attach the prior verified Protocol 2.2 result only as a cross-check. Verify full/portable complete-tree parity and have a qualified attorney assess handoff usefulness and follow-up sufficiency. Do not copy private sources, reports, responses, matrices, identifiers, hashes, or results into fixtures, docs, commits, logs, or public verification artifacts.

Expected: this gate supplies private rollout evidence only. It does not change the default protocol, publish a package, or authorize release.

- [ ] **Step 10: Commit package and gate enforcement**

```bash
git add scripts/skill-package-files.txt scripts/build_skill.py scripts/audit_release.py tests/scripts/test_build_skill.py tests/scripts/test_audit_release.py docs/release-checklist.md
git commit -m "test: gate readiness packaging and compatibility"
```

---

## Final Acceptance Checklist

- [ ] Every report revision is graded by two fresh readiness-owned lanes against `verify_gradeable_baseline_projection_v1(...)`; no new or matching Protocol 2.2 run is required and no retained Protocol 2.2 artifact/command is written or changed.
- [ ] `baseline_locked_strict_equivalent_disposition` reproduces retained Protocol 2.2 scoring, lane-merging, reason-code, and contested-sensitivity semantics while remaining explicitly labeled a `delivery-readiness-v1` strict-equivalent result.
- [ ] Optional `historical_v22_strict_disposition` is separately preserved with `NOT_PROVIDED`, `BASELINE_NOT_COMPARABLE`, `REPORT_NOT_COMPARABLE`, `MATCH`, or `DISPOSITION_DIFFERS`; it never seeds fresh grades or changes matrices, readiness, blockers, or exit code.
- [ ] All three readiness tiers are exercised in full and portable synthetic runs; exact `0.70`, `0.90`, and `1.0` boundaries are mutation-sensitive.
- [ ] Every lane-level partial/missing/uncertain, baseline gap, contested item, prerequisite limitation, and safety finding has one deterministic matrix row and follow-up.
- [ ] Every accepted row has specific evidence-bound `why_unresolved`, `why_it_matters`, and `resolution_test`; generic/evidence-unbound text blocks delivery without controller-authored replacement prose.
- [ ] Two fresh baseline-locked grading lanes and two fresh safety lanes always run; every safety disagreement is visible and requires one fresh dispute-scoped referee.
- [ ] `REVIEW_READY_WITH_GAPS` may coexist with fresh strict-equivalent `FAIL` or substantive `INCONCLUSIVE`, exits `0`, and is never displayed as `PASS` or client-delivery authorization.
- [ ] `NOT_DELIVERABLE` exits `4`, preserves sealed artifacts, suppresses the report as attorney work product, and exposes only allowlisted blocker/remediation metadata.
- [ ] Second mechanical refusal leaves the exact request pending, writes no rejected bytes, creates no result, and exits `6`.
- [ ] The readiness graph is a separate sibling; Protocol 1.3/2.0/2.1/2.2 and stable-baseline trees remain byte-identical and read-only.
- [ ] Replay detects tamper/reseal/swap/orphan/race/link/root/inventory attacks and derives exact matrices, result, Markdown, verification, and manifest.
- [ ] Full and isolated-portable requests, accepted responses, artifacts, status, verification, exits, Markdown, and complete trees are byte-identical while reading the same packaged rubric asset.
- [ ] Protocol 2.1 remains the default and no implementation test claims publication, production maturity, legal correctness, or permission for unreviewed client delivery.
- [ ] Public fixtures are licensed and synthetic; private evaluation work product remains outside the repository and built archives.
- [ ] Calibration records at least three, preferably five, attorney-reviewed cases before any threshold change; any change uses a new rubric version and never rewrites historical results.
- [ ] Full pytest, Ruff, mypy, wheel/sdist, reproducible skill ZIP, isolated package, privacy, reachable-history, and manual authorization gates are complete before any separate release decision.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
