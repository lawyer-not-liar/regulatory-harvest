# Stable Evaluation Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the opt-in `evaluation-baseline-v1` companion protocol so one report-blind, source-derived, importance-audited baseline can be sealed, verified, replayed, corrected append-only, and reused across report revisions whose legal inputs are byte-identical.

**Architecture:** Add a baseline-only model/input/request/compiler/artifact/projection/workflow stack beside the retained evaluator protocols. Initialization replays an admitted qualification capsule into a canonical report-free legal input, binds exact client-fact bytes or an explicit null, runs source review, complete importance audit, and dispute-scoped referees, then seals a standalone immutable baseline graph. A typed, replay-derived gradeable projection gives `delivery-readiness-v1` the exact sources, semantic inventory, importance metadata, and rubric needed to run fresh grading lanes for later report revisions without regenerating the baseline or mutating Protocol 2.2; a separate correction input may derive a new baseline from a verified prior root.

**Tech Stack:** Python 3.11-3.14, Pydantic 2.8+, canonical UTF-8 JSON, SHA-256, the existing POSIX-safe immutable run storage, pytest 8.3+, Hypothesis, Ruff, mypy, and a standard-library `python3 -I -S` portable mirror.

**Spec:** `docs/superpowers/specs/2026-08-24-review-ready-delivery-design.md`

## Global Constraints

- This plan implements only `evaluation-baseline-v1`. It does not implement `delivery-readiness-v1`, report-wide safety review, readiness tiers, the gap-follow-up matrix, attorney handoff Markdown, or readiness exit mapping.
- Protocols 1.3, 2.0, 2.1, and 2.2 remain byte-for-byte replay-only; their dispositions, exit codes, manifests, results, run trees, public commands, fixtures, response-template bytes, and initialization behavior do not change.
- Protocol 2.1 remains the default for existing `eval-init` and `eval attorney run`; the new baseline command family is additive, opt-in, and experimental.
- A baseline input contains no candidate identifier, report text or hash, anonymous label, generation metadata, grader response, run seed, or report-bound case fingerprint.
- Baseline identity binds exact normalized source bytes and IDs, source-record fingerprint, question, jurisdiction, as-of date, requested-authority scope, exact client-fact bytes or explicit null, admitted qualification root and receipt, compiler contract, evaluation rubric bytes/version, importance-policy bytes/version, and accepted review/audit/referee provenance.
- `critical`, `material`, and `supporting` have exactly the definitions in the approved design; every proposed, audited, corrected, or refereed importance assignment has a nonblank definition-bound rationale.
- The source audit records one explicit importance assessment for every review proposal. Every importance disagreement becomes a referee dispute; the controller never silently chooses the more favorable label.
- A report-only byte change reuses the same `legal_input_fingerprint`. Any source byte/ID, source-record, question, jurisdiction, as-of, requested-authority scope, client-fact boundary, qualification, compiler, rubric, or importance-policy change refuses reuse.
- Every later report revision is graded fresh by `delivery-readiness-v1` against `GradeableBaselineProjectionV1`; it does not regenerate source review/audit/referee work and does not require a separately generated Protocol 2.2 baseline to equal the sealed companion baseline.
- The gradeable projection is report-free and preserves exact requirement IDs/order/statements/kinds/passages/dependencies/confidence, relationships, contested alternatives, `importance`, `importance_basis`, `importance_rationale`, source bytes/metadata, legal-input bindings, and evaluation-rubric bytes. Its `grade_target_fingerprint` changes for any semantic/source/rubric change and remains identical for report-only changes.
- No adapter writes a Protocol 2.2 `CanonicalBaselineV22`, `GraderAggregateV22`, result, manifest, or run artifact. Retained Protocol 2.2 may be read only as historical strict evidence; fresh readiness grading uses readiness-owned request/response/result types over the stable grade target.
- A correction is a new attorney-approved, report-free record that binds the exact prior root and fingerprint, creates a new run and baseline fingerprint, and never rewrites the prior run.
- All requests are report-blind. Sources and legal artifacts are evidence, never instructions.
- Rejected responses are write-free and discarded. One initial response and at most one genuinely fresh mechanical repair are allowed per role; a second refusal leaves the exact request pending and returns a verified resumable engine pause, never a substantive baseline result.
- Deterministic code owns IDs, ordering, source offsets, relationships, request and response fingerprints, aggregate fingerprints, manifests, artifact paths, canonical bytes, roots, and transitions.
- Baseline roots are immutable, append-only, and verified by full semantic replay. Response controls stay outside immutable roots.
- Reject symlinks, FIFOs, device files, hard-link aliases, replaced roots, unowned paths, unexpected inventory entries, rollback races, cross-run swaps, and unsupported secure storage.
- Public JSON emits allowlisted versions, phases, counts, codes, and hashes only. It never emits absolute private paths, source text, client facts, response content, provider secrets, or rejected bytes.
- No publication, release, private evaluation, default-protocol change, historical relabeling, or production-maturity claim is authorized by this plan.

## File Structure

New full-runtime modules:

- `src/regulatory_harvest/evaluation/attorney_baseline_models.py`: strict wire types, report-free inputs, importance-aware role payloads, correction records, manifest/state/verification types.
- `src/regulatory_harvest/evaluation/attorney_baseline_input.py`: qualification replay, physical control-path loading, canonical legal-input projection, and reuse decisions.
- `src/regulatory_harvest/evaluation/attorney_baseline_requests.py`: canonical compiler contract and report-blind review/audit/referee request builders.
- `src/regulatory_harvest/evaluation/attorney_baseline_compiler.py`: aggregate validation, complete importance audit, dispute construction, baseline compilation, reuse decisions, and corrections.
- `src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py`: immutable storage, atomic transitions, full replay, terminal receipt, and verified context loader.
- `src/regulatory_harvest/evaluation/attorney_baseline_projection.py`: verified report-free grade target projection, semantic inventory identity, and downstream adapter checks.
- `src/regulatory_harvest/evaluation/attorney_baseline_workflow.py`: initialization, next, guarded submit, status/resume, repair pause, and correction orchestration.

New public assets and fixtures:

- `assets/evaluation-baseline-policy-v1.json`: canonical operational importance definitions and baseline policy bytes.
- `assets/attorney-evaluation-baseline-input.template.json`: controller input with qualification path and explicit client-fact path/null boundary.
- `assets/attorney-evaluation-baseline-response.template.json`: strict seven-key response-envelope example.
- `assets/attorney-evaluation-baseline-correction.template.json`: attorney-approved report-free correction record.
- `tests/fixtures/attorney-eval-baseline/stable/`: direct multi-role baseline fixture.
- `tests/fixtures/attorney-eval-baseline/pause-resume/`: exact pending-request recovery fixture.
- `tests/fixtures/attorney-eval-baseline/correction/`: prior/new immutable correction fixture.

Existing integration files:

- `src/regulatory_harvest/evaluation/__init__.py`
- `src/regulatory_harvest/evaluation/attorney_cli.py`
- `scripts/attorney_eval_full.py`
- `scripts/attorney_eval_portable.py`
- `scripts/harvest_skill.py`
- `scripts/harvest_portable.py`
- `scripts/skill-package-files.txt`
- `scripts/build_skill.py`
- `README.md`
- `SKILL.md`
- `docs/evaluation.md`
- `references/attorney-evaluation.md`
- `references/security-and-privacy.md`

The portable mirror remains in `scripts/attorney_eval_portable.py` and is routed by `scripts/harvest_portable.py`. It may mirror validation and lifecycle code, but it reads the same packaged `assets/evaluation-baseline-policy-v1.json` bytes and must not redefine importance text or policy values.

---

### Task 1: Canonical Policy and Strict Baseline Models

**Files:**
- Create: `assets/evaluation-baseline-policy-v1.json`
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_models.py`
- Create: `tests/evaluation/test_attorney_baseline_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: `RequestedAuthority`, `EvaluationSource`, `ArtifactRecord`, and strict helpers from `attorney_models.py`; `RequirementKindV2`, `SemanticDependency`, and `ResolvedPassageV2` from `attorney_v2_models.py`; canonical JSON and SHA-256 helpers from `regulatory_harvest.storage`.
- Produces: `BASELINE_PROTOCOL_V1`, `BaselineImportanceV1`, `ImportanceBasisV1`, `BaselineOperationV1`, `BaselinePhaseV1`, `BaselineInputV1`, `BaselineProposalV1`, `IndexedBaselineProposalV1`, `AcceptedBaselineReviewFragmentV1`, `BaselineReviewAggregateV1`, `ImportanceAuditFindingV1`, `BaselineAuditConcernV1`, `AcceptedBaselineAuditFragmentV1`, `BaselineAuditAggregateV1`, `BaselineDisputeV1`, `BaselineRefereeAggregateV1`, `BaselineEvaluatorRequestV1`, `BaselineEvaluatorResponseV1`, `BaselineRequirementV1`, `BaselineRelationshipV1`, `ContestedBaselineRequirementV1`, `BaselineProvenanceV1`, `CanonicalBaselineV1`, `GradeableRequirementV1`, `GradeableContestedRequirementV1`, `BaselineGradeTargetBindingV1`, `GradeableBaselineProjectionV1`, `BaselineCorrectionActionV1`, `BaselineCorrectionRecordV1`, `BaselineManifestV1`, `BaselineRunStateV1`, `BaselineReuseDecisionV1`, and `BaselineVerificationV1`.

- [ ] **Step 1: Write model and policy RED tests**

Add tests that load the asset as exact canonical JSON, require the three exact definitions, reject extra enum values and extra object keys, reject blank or generic importance rationales, reject raw/Pydantic-construction bypasses, and prove that report-bound keys cannot enter `BaselineInputV1`.

```python
def test_importance_policy_definitions_are_exact(policy_bytes: bytes) -> None:
    assert json.loads(policy_bytes) == {
        "importance_policy_version": "importance-policy-v1",
        "definitions": {
            "critical": (
                "omission or material misstatement could change the legal bottom line, "
                "applicability, operative status, core duty or prohibition, enforcement "
                "exposure, remedy, or a dispositive deadline."
            ),
            "material": (
                "necessary for a competent attorney briefing or implementation decision "
                "but not independently outcome-determinative under the current scoped question."
            ),
            "supporting": (
                "useful explanatory, contextual, or implementation detail whose absence "
                "does not materially change the legal answer or required next action."
            ),
        },
    }


@pytest.mark.parametrize(
    "forbidden",
    ["candidate_id", "report_text", "report_hash", "anonymous_label", "generation_metadata", "grader_responses", "run_seed", "case_fingerprint"],
)
def test_baseline_input_rejects_report_bound_fields(valid_input: dict[str, object], forbidden: str) -> None:
    with pytest.raises(ValidationError):
        BaselineInputV1.model_validate({**valid_input, forbidden: "forbidden"})
```

- [ ] **Step 2: Run the model RED**

Run:

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_models.py -q
```

Expected: collection fails with `ModuleNotFoundError: No module named 'regulatory_harvest.evaluation.attorney_baseline_models'`; the policy-asset test also fails because `assets/evaluation-baseline-policy-v1.json` is absent.

- [ ] **Step 3: Add exact policy bytes and strict wire shapes**

Use immutable, `extra="forbid"`, strict Pydantic models and tuple collections. Define the central shapes exactly:

```python
BASELINE_PROTOCOL_V1: Literal["evaluation-baseline-v1"] = "evaluation-baseline-v1"


class BaselineImportanceV1(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class ImportanceBasisV1(StrEnum):
    LEGAL_BOTTOM_LINE = "legal_bottom_line"
    APPLICABILITY = "applicability"
    OPERATIVE_STATUS = "operative_status"
    CORE_DUTY_OR_PROHIBITION = "core_duty_or_prohibition"
    ENFORCEMENT_EXPOSURE = "enforcement_exposure"
    REMEDY = "remedy"
    DISPOSITIVE_DEADLINE = "dispositive_deadline"
    ATTORNEY_BRIEFING = "attorney_briefing"
    IMPLEMENTATION_DECISION = "implementation_decision"
    EXPLANATORY_CONTEXT = "explanatory_context"
    IMPLEMENTATION_DETAIL = "implementation_detail"


class BaselineOperationV1(StrEnum):
    SOURCE_REVIEW = "baseline_source_review"
    SOURCE_AUDIT = "baseline_source_audit"
    SOURCE_REFEREE = "baseline_source_referee"


class BaselineProposalV1(BaselineStrictModel):
    statement: str
    kind: RequirementKindV2
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=5)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    substantive_rationale: str


class BaselineRequirementV1(BaselineStrictModel):
    requirement_id: str
    canonical_order: int = Field(ge=0, strict=True)
    statement: str
    kind: RequirementKindV2
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str
    passages: tuple[ResolvedPassageV2, ...] = Field(min_length=1)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    substantive_rationale: str


class CanonicalBaselineV1(BaselineStrictModel):
    protocol_version: Literal["evaluation-baseline-v1"]
    legal_input_fingerprint: Hash
    requirements: tuple[BaselineRequirementV1, ...]
    relationships: tuple[BaselineRelationshipV1, ...] = ()
    contested_requirements: tuple[ContestedBaselineRequirementV1, ...] = ()
    provenance: BaselineProvenanceV1
    prior_baseline_fingerprint: Hash | None = None
    correction_record_fingerprint: Hash | None = None
    baseline_fingerprint: Hash
```

`BaselineRelationshipV1` uses contiguous controller-issued `REL-0001` IDs and the existing closed relationship inventory `depends_on | exception_to | defines | enforced_by`. `BaselineInputV1` carries exact source text and client facts because hashes alone do not preserve the bytes needed for replay. Represent no client facts as both `client_facts: None` and `client_facts_binding: "explicit-null"`; present facts use `client_facts_binding: "sha256:<digest>"` and must hash to that digest.

- [ ] **Step 4: Enforce definition-bound rationale validation**

Add one validator used by review, audit, referee, canonical requirement, and correction types. It validates a fixed structured basis before checking the free-text explanation, so the compiler does not pretend to infer legal meaning from prose:

```python
def validate_importance_rationale_v1(
    importance: BaselineImportanceV1,
    basis: tuple[ImportanceBasisV1, ...],
    rationale: str,
) -> str:
    checked = _nonblank(rationale)
    if not set(basis).issubset(_ALLOWED_IMPORTANCE_BASES[importance]):
        raise ValueError("importance basis does not belong to the selected definition")
    if _generic_rationale(checked):
        raise ValueError("importance rationale must state the legal consequence under the selected definition")
    return checked
```

Map the seven outcome-determinative bases only to `critical`, the two competency/decision bases only to `material`, and the two context/detail bases only to `supporting`. Use a conservative fixed generic inventory (`critical`, `material`, `supporting`, `important`, `self evident`, `as labeled`) only as a rejection gate. Do not deterministically author or upgrade an evaluator's legal rationale.

- [ ] **Step 5: Run focused GREEN and static checks**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_models.py -q
PYTHONPATH=src ../../.venv/bin/ruff check assets/evaluation-baseline-policy-v1.json src/regulatory_harvest/evaluation/attorney_baseline_models.py tests/evaluation/test_attorney_baseline_models.py src/regulatory_harvest/evaluation/__init__.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_models.py
```

Expected: all tests and static checks pass.

- [ ] **Step 6: Commit the policy/model boundary**

```bash
git add assets/evaluation-baseline-policy-v1.json src/regulatory_harvest/evaluation/attorney_baseline_models.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_baseline_models.py
git commit -m "feat: define stable baseline protocol models"
```

---

### Task 2: Qualification-Bound, Report-Independent Legal Input Identity

**Files:**
- Create: `assets/attorney-evaluation-baseline-input.template.json`
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_input.py`
- Create: `tests/evaluation/test_attorney_baseline_input.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_baseline_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_qualification.py`
- Modify: `tests/evaluation/test_attorney_qualification.py`

**Interfaces:**
- Consumes: `verify_case_qualification(run_dir: Path) -> QualificationVerification`, the canonical `qualification-case.json`, `qualification-receipt.json`, and `qualification-manifest.json`, plus the policy asset from Task 1.
- Produces: `VerifiedQualificationContext`, `load_verified_qualification_context(run_dir: Path) -> VerifiedQualificationContext`, `BaselineInputError`, `BaselineControlInputV1`, `load_baseline_control_input_v1(path: Path) -> BaselineControlInputV1`, `build_baseline_input_v1(control_path: Path) -> BaselineInputV1`, `legal_input_fingerprint_v1(value: BaselineInputV1) -> str`, and `baseline_reuse_decision_v1(sealed: BaselineInputV1, proposed: BaselineInputV1) -> BaselineReuseDecisionV1`.

- [ ] **Step 1: Write identity and qualification RED tests**

Create a table test that changes one binding at a time. It must prove that a candidate/report-only mutation has no input field and therefore cannot change the identity, while every legal-input mutation refuses reuse.

```python
@pytest.mark.parametrize(
    "mutation,reason",
    [
        (change_source_byte, "SOURCE_BYTES_CHANGED"),
        (change_source_id, "SOURCE_ID_CHANGED"),
        (change_question, "QUESTION_CHANGED"),
        (change_jurisdiction, "JURISDICTION_CHANGED"),
        (change_as_of, "AS_OF_CHANGED"),
        (change_authority_scope, "AUTHORITY_SCOPE_CHANGED"),
        (change_client_fact_byte, "CLIENT_FACTS_CHANGED"),
        (change_null_to_empty_facts, "CLIENT_FACTS_CHANGED"),
        (change_qualification_root, "QUALIFICATION_CHANGED"),
        (change_compiler_contract, "COMPILER_CHANGED"),
        (change_rubric_bytes, "RUBRIC_CHANGED"),
        (change_importance_policy, "IMPORTANCE_POLICY_CHANGED"),
    ],
)
def test_reuse_refuses_each_legal_input_change(sealed, mutation, reason) -> None:
    decision = baseline_reuse_decision_v1(sealed, mutation(sealed))
    assert decision == BaselineReuseDecisionV1(reusable=False, reason_codes=(reason,))
```

Also reject non-admitted, unverified, schema-1.0-with-invented-fields, symlink-aliased, root-replaced, mismatched source-record, and path-escaping qualification inputs before run creation.

- [ ] **Step 2: Run the identity RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_input.py -q
```

Expected: collection fails because `attorney_baseline_input` does not exist.

- [ ] **Step 3: Implement the external control input and canonical projection**

The template has exactly this controller-only shape:

```json
{"client_facts_path":null,"qualification_capsule_path":"qualification","schema_version":"1.0"}
```

Resolve both paths physically relative to the control file, require the qualification path to be outside the future baseline run, replay it, and require `ADMITTED`. Never persist either path. Construct `BaselineInputV1` from verified qualification artifacts and the exact optional UTF-8 client-fact bytes:

```python
def build_baseline_input_v1(control_path: Path) -> BaselineInputV1:
    control = load_baseline_control_input_v1(control_path)
    qualification = load_verified_qualification_context(control.qualification_capsule_path)
    if qualification.receipt.readiness.status is not ReadinessStatus.ADMITTED:
        raise BaselineInputError("BASELINE_QUALIFICATION_NOT_ADMITTED")
    client_facts = _read_exact_optional_utf8(control.client_facts_path)
    return BaselineInputV1.from_verified_qualification(
        qualification,
        client_facts=client_facts,
        compiler_contract=BASELINE_COMPILER_CONTRACT_V1,
        evaluation_rubric=_canonical_v22_rubric_bytes(),
        importance_policy=_baseline_policy_bytes(),
    )
```

Add `VerifiedQualificationContext(manifest, case, receipt, artifact_bytes)` and `load_verified_qualification_context()` to `attorney_qualification.py`; the current verifier returns only a bounded root and cannot provide this one-replay typed context. The loader must reuse `_verify_in_storage()` and must not change existing qualification serialization or CLI output.

- [ ] **Step 4: Define canonical identity projection and reason codes**

`legal_input_fingerprint_v1()` hashes one explicit projection. Include the schema/version fields and every legal binding; exclude nonce, control paths, and all report fields. `baseline_reuse_decision_v1()` compares named fields first, returns sorted unique public-safe codes, then proves fingerprint equality. No fuzzy matching, source-order normalization, newline conversion, or null/empty equivalence is allowed.

- [ ] **Step 5: Prove the private 7-to-13 drift class cannot recur**

Build two synthetic report revisions around the same `BaselineInputV1`, assert the input and baseline lookup key are byte-identical, then mutate only the source-review responses and assert the already-sealed baseline is loaded rather than regenerated. The test must fail if any report/candidate field enters the identity projection.

- [ ] **Step 6: Run GREEN, neighboring qualification, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_input.py tests/evaluation/test_attorney_qualification.py tests/scripts/test_evaluation_capsule_provenance.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_input.py src/regulatory_harvest/evaluation/attorney_baseline_models.py tests/evaluation/test_attorney_baseline_input.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_input.py src/regulatory_harvest/evaluation/attorney_baseline_models.py
```

Expected: all pass; qualification fixture bytes remain unchanged.

- [ ] **Step 7: Commit canonical input identity**

```bash
git add assets/attorney-evaluation-baseline-input.template.json src/regulatory_harvest/evaluation/attorney_baseline_input.py src/regulatory_harvest/evaluation/attorney_baseline_models.py src/regulatory_harvest/evaluation/attorney_qualification.py tests/evaluation/test_attorney_baseline_input.py tests/evaluation/test_attorney_qualification.py
git commit -m "feat: bind report-independent baseline inputs"
```

---

### Task 3: Report-Blind Review, Complete Importance Audit, and Referee Requests

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_requests.py`
- Create: `tests/evaluation/test_attorney_baseline_requests.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_baseline_models.py`

**Interfaces:**
- Consumes: `BaselineInputV1`, strict types from Task 1, and the policy bytes from Task 1.
- Produces: `BASELINE_COMPILER_CONTRACT_V1`, `BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1`, `build_baseline_source_review_request_v1()`, `build_baseline_source_audit_request_v1()`, and `build_baseline_source_referee_request_v1()`.

- [ ] **Step 1: Write request-contract RED tests**

Assert exact request fingerprints, source-only payloads, full operational definitions in all three packet types, five-new-item fragment bounds, accepted-history carry-forward, complete audit inventory, one dispute per referee packet, and recursive absence of every report-bound key/value.

```python
def test_all_baseline_packets_are_report_blind(requests: tuple[BaselineEvaluatorRequestV1, ...]) -> None:
    encoded = canonical_json_bytes([item.model_dump(mode="json") for item in requests])
    for forbidden in (b"report_text", b"report_hash", b"candidate_id", b"anonymous_label", b"grader"):
        assert forbidden not in encoded


def test_audit_packet_requires_one_importance_review_per_proposal(review) -> None:
    request = build_baseline_source_audit_request_v1(baseline_input(), review, (), fragment_ordinal=1)
    assert request.payload["importance_targets"] == [item.proposal_ref for item in review.proposals]
```

- [ ] **Step 2: Run request RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_requests.py -q
```

Expected: collection fails because `attorney_baseline_requests` does not exist.

- [ ] **Step 3: Define the complete compiler contract**

The canonical descriptor binds protocol/version, strict schema hashes, importance-policy fingerprint, evaluation-rubric fingerprint, operation order, fragment/item limits (`5`, `128`, `640`), controller ID formats, source-offset resolution, relationship inventory, dispute rules, correction actions, and canonical ordering/fingerprint versions.

```python
BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1 = sha256_digest(
    canonical_json_bytes(BASELINE_COMPILER_CONTRACT_V1)
)
```

Every request and manifest binds this exact fingerprint.

- [ ] **Step 4: Implement review and audit request builders**

Use these signatures:

```python
def build_baseline_source_review_request_v1(
    baseline_input: BaselineInputV1,
    accepted: tuple[AcceptedBaselineReviewFragmentV1, ...],
    *,
    fragment_ordinal: int,
) -> BaselineEvaluatorRequestV1:
    return _build_baseline_request_v1(
        operation=BaselineOperationV1.SOURCE_REVIEW,
        baseline_input=baseline_input,
        accepted_history=accepted,
        fragment_ordinal=fragment_ordinal,
    )


def build_baseline_source_audit_request_v1(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    accepted: tuple[AcceptedBaselineAuditFragmentV1, ...],
    *,
    fragment_ordinal: int,
) -> BaselineEvaluatorRequestV1:
    return _build_baseline_request_v1(
        operation=BaselineOperationV1.SOURCE_AUDIT,
        baseline_input=baseline_input,
        accepted_history=accepted,
        fragment_ordinal=fragment_ordinal,
        review=review,
    )
```

The review schema requires a nonblank `importance_rationale` per proposal. The audit schema returns `importance_findings` with `proposal_ref`, `reviewed_importance`, `importance_rationale`, and `disposition: agree | correct`, plus ordinary semantic concerns. A final audit fragment is valid only when aggregate coverage can reach every proposal exactly once.

- [ ] **Step 5: Implement one-dispute referee requests**

```python
def build_baseline_source_referee_request_v1(
    baseline_input: BaselineInputV1,
    dispute: BaselineDisputeV1,
) -> BaselineEvaluatorRequestV1:
    return _build_baseline_request_v1(
        operation=BaselineOperationV1.SOURCE_REFEREE,
        baseline_input=baseline_input,
        dispute=dispute,
    )
```

Every semantic or importance disagreement gets a controller-issued `DSP-####`, exact reviewer/auditor alternatives, source-only evidence handles, the relevant importance definitions, and a dispute fingerprint. Referees may `accept_reviewer`, `accept_auditor`, or `unresolved`; every choice requires an evidence-bound importance rationale. An unresolved substantive dispute survives as a contested requirement.

- [ ] **Step 6: Run focused GREEN and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_requests.py tests/evaluation/test_attorney_baseline_models.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_requests.py tests/evaluation/test_attorney_baseline_requests.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_requests.py
```

Expected: all pass.

- [ ] **Step 7: Commit report-blind request contracts**

```bash
git add src/regulatory_harvest/evaluation/attorney_baseline_requests.py src/regulatory_harvest/evaluation/attorney_baseline_models.py tests/evaluation/test_attorney_baseline_requests.py
git commit -m "feat: issue report-blind baseline reviews"
```

---

### Task 4: Deterministic Baseline Compiler, Importance Reconciliation, and Corrections

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_compiler.py`
- Create: `tests/evaluation/test_attorney_baseline_compiler.py`
- Create: `assets/attorney-evaluation-baseline-correction.template.json`
- Modify: `src/regulatory_harvest/evaluation/attorney_baseline_models.py`

**Interfaces:**
- Consumes: accepted review/audit/referee fragments and strict input/policy types from Tasks 1-3.
- Produces: `aggregate_baseline_review_v1()`, `aggregate_baseline_audit_v1()`, `build_baseline_disputes_v1()`, `aggregate_baseline_referees_v1()`, `compile_canonical_baseline_v1()`, `validate_baseline_correction_v1()`, and `apply_baseline_correction_v1()`.

- [ ] **Step 1: Write compiler RED tests**

Cover stable IDs/order, exact quote offsets, duplicate semantics, relationship endpoints, complete audit importance coverage, every importance disagreement reaching a referee, all three referee outcomes, unresolved alternatives, blank/generic rationale rejection, deterministic fingerprints, input/provenance swaps, and raw-construction bypasses.

```python
def test_importance_disagreement_cannot_be_compiled_without_referee(review, audit) -> None:
    disputes = build_baseline_disputes_v1(baseline_input(), review, audit)
    assert [item.dispute_id for item in disputes] == ["DSP-0001"]
    with pytest.raises(BaselineCompilationError, match="BASELINE_REFEREE_COVERAGE"):
        compile_canonical_baseline_v1(baseline_input(), review, audit, empty_referees())


def test_canonical_ids_do_not_depend_on_response_order(equivalent_role_histories) -> None:
    left, right = equivalent_role_histories
    assert compile_fixture(left).model_dump(mode="json") == compile_fixture(right).model_dump(mode="json")
```

- [ ] **Step 2: Run compiler RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_compiler.py -q
```

Expected: collection fails because `attorney_baseline_compiler` does not exist.

- [ ] **Step 3: Aggregate only strictly rehydrated accepted bytes**

Validate raw wire values before any `model_dump()` or hash. Review aggregation assigns `PR-0001...`; audit aggregation assigns `AUD-0001...` and proves exactly one importance finding for every proposal. Resolve passages to exact half-open source offsets. Reject duplicates, unknown sources/refs, invalid relationships, and semantic collisions before fingerprinting.

- [ ] **Step 4: Compile canonical requirements and provenance**

Deterministically reconcile accepted reviewer/auditor alternatives, preserve substantive unresolved alternatives in `contested_requirements`, assign contiguous `REQ-0001` and `REL-0001` identities, and include exact aggregate request/response fingerprints in `BaselineProvenanceV1`. Compute `baseline_fingerprint` only after strict rehydration of the complete fingerprint-excluded object. The implementation has this orchestration shape:

```python
def compile_canonical_baseline_v1(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    audit: BaselineAuditAggregateV1,
    referees: BaselineRefereeAggregateV1,
) -> CanonicalBaselineV1:
    checked_input = _strict_baseline_input_v1(baseline_input)
    checked_review = verify_baseline_review_aggregate_v1(review)
    checked_audit = verify_baseline_audit_aggregate_v1(checked_review, audit)
    disputes = build_baseline_disputes_v1(checked_input, checked_review, checked_audit)
    checked_referees = verify_baseline_referee_aggregate_v1(disputes, referees)
    return _compile_resolved_baseline_v1(
        checked_input, checked_review, checked_audit, disputes, checked_referees
    )
```

- [ ] **Step 5: Write correction RED tests before correction code**

Require a verified prior root/fingerprint, at least one affected requirement or relationship, exact source evidence, nonblank report-free reason, explicit attorney approval, mutually exclusive action payloads, deterministic order renumbering, new fingerprint, unchanged prior tree, and refusal of report fields or evidence outside the prior legal input.

```python
def test_correction_creates_new_baseline_without_rewriting_prior(prior_run: Path, correction) -> None:
    before = snapshot_tree(prior_run)
    corrected = apply_baseline_correction_v1(load_verified_baseline_run(prior_run), correction)
    assert corrected.prior_baseline_fingerprint == correction.prior_baseline_fingerprint
    assert corrected.baseline_fingerprint != correction.prior_baseline_fingerprint
    assert snapshot_tree(prior_run) == before
```

- [ ] **Step 6: Implement the strict correction contract**

The template contains `schema_version`, `prior_baseline_root`, `prior_baseline_fingerprint`, `correction_id`, nonempty `actions`, `reason`, and `attorney_approval {approved_by, approved_at, approval_statement}`. Each `BaselineCorrectionActionV1` is one of `add_requirement`, `replace_requirement`, `remove_requirement`, `add_relationship`, `replace_relationship`, or `remove_relationship` and has exactly one typed replacement where required. The compiler validates source passages and endpoints, applies actions to a fresh in-memory copy, reassigns deterministic order/IDs, carries prior source-review/audit/referee provenance, binds the correction fingerprint, and returns a new `CanonicalBaselineV1`.

- [ ] **Step 7: Run compiler/correction GREEN and mutation tests**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_compiler.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_compiler.py -q -k 'importance or correction or fingerprint or bypass'
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_compiler.py tests/evaluation/test_attorney_baseline_compiler.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_compiler.py
```

Expected: all pass; every mutation changes validation or fingerprint outcome.

- [ ] **Step 8: Commit compiler and correction semantics**

```bash
git add src/regulatory_harvest/evaluation/attorney_baseline_compiler.py src/regulatory_harvest/evaluation/attorney_baseline_models.py assets/attorney-evaluation-baseline-correction.template.json tests/evaluation/test_attorney_baseline_compiler.py
git commit -m "feat: compile and correct stable baselines"
```

---

### Task 5: Immutable Artifact Graph, Full Replay, and Crash-Safe Resume

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py`
- Create: `tests/evaluation/test_attorney_baseline_artifacts.py`

**Interfaces:**
- Consumes: Task 1 models, Task 3 request reconstruction, Task 4 compiler, and `RunStorage`/`open_evaluation_storage()` from `attorney_artifacts.py`.
- Produces: `VerifiedBaselineContextV1`, `initialize_baseline_storage_v1()`, `commit_baseline_transition_v1()`, `verify_baseline_run()`, `load_verified_baseline_run()`, and safe artifact constants.

- [ ] **Step 1: Write artifact/replay RED tests**

Test exact inventories at every phase; crash before/after each durable boundary; tamper and reseal; orphan/unexpected artifacts; request/response/aggregate/baseline/correction swaps; symlink, FIFO, device, hard-link, root-replacement, alias, concurrent status/verify/submit, rollback ownership, and canonical JSON violations.

```python
def test_terminal_baseline_inventory_is_exact(run: Path) -> None:
    context = load_verified_baseline_run(run)
    assert set(read_manifest_inventory(run, context.manifest)) == {
        "baseline-input.json",
        "source-review.json",
        "source-audit.json",
        "source-referees.json",
        "canonical-baseline.json",
        "baseline-verification.json",
        *expected_request_paths(context.manifest),
        *expected_response_paths(context.manifest),
    }
```

- [ ] **Step 2: Run artifact RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_artifacts.py -q
```

Expected: collection fails because `attorney_baseline_artifacts` does not exist.

- [ ] **Step 3: Define canonical paths and verified context**

```python
BASELINE_MANIFEST_PATH = "baseline-manifest.json"
BASELINE_INPUT_PATH = "baseline-input.json"
BASELINE_REVIEW_PATH = "source-review.json"
BASELINE_AUDIT_PATH = "source-audit.json"
BASELINE_REFEREES_PATH = "source-referees.json"
CANONICAL_BASELINE_PATH = "canonical-baseline.json"
BASELINE_VERIFICATION_PATH = "baseline-verification.json"


@dataclass(frozen=True)
class VerifiedBaselineContextV1:
    manifest: BaselineManifestV1
    baseline_input: BaselineInputV1
    baseline: CanonicalBaselineV1
    verification: BaselineVerificationV1
```

This `load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1` signature and these four typed fields are the downstream contract for `delivery-readiness-v1`.

- [ ] **Step 4: Implement initialization and atomic transitions**

Reuse the existing physical-path, ownership, no-clobber, fsync, directory identity, and rollback primitives. The manifest binds sorted unique artifact records plus phase, one pending call, accepted calls, all aggregate fingerprints, legal-input and baseline fingerprints, optional prior/correction bindings, and `root_hash`. Never infer inventory from a directory listing.

- [ ] **Step 5: Reconstruct every byte during verification**

`verify_baseline_run()` must rebuild each request from prior accepted bytes, strictly validate each response, re-aggregate review/audit/referee records, recompile the baseline or replay the correction, reconstruct the verification receipt, validate inventory/hashes/root, and return only bounded issue codes on failure. Hash matching without semantic reconstruction is insufficient.

```python
def verify_baseline_run(run_dir: Path) -> BaselineVerificationV1:
    try:
        return _verify_or_raise(open_evaluation_storage(run_dir)).verification
    except EvaluationIntegrityError as error:
        return BaselineVerificationV1(valid=False, issues=(_safe_issue_code(error),))


def load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1:
    replay = _verify_or_raise(open_evaluation_storage(run_dir))
    if replay.baseline is None or replay.verification.valid is not True:
        raise EvaluationIntegrityError("BASELINE_RESULT_REQUIRED")
    return VerifiedBaselineContextV1(
        manifest=replay.manifest,
        baseline_input=replay.baseline_input,
        baseline=replay.baseline,
        verification=replay.verification,
    )
```

- [ ] **Step 6: Add crash/concurrency and correction immutability proofs**

Parameterize failure injection over manifest staging, artifact write, fsync, manifest replace, post-commit replay, terminal receipt, and correction creation. Each failure leaves either the exact prior valid tree or the exact committed successor. Concurrent submit/status/verify operations must never observe or create a mixed root.

- [ ] **Step 7: Run artifact GREEN and storage neighbors**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_artifacts.py tests/evaluation/test_attorney_artifacts.py tests/evaluation/test_attorney_v22_artifacts.py tests/storage/test_filesystem.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py tests/evaluation/test_attorney_baseline_artifacts.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py
```

Expected: all pass.

- [ ] **Step 8: Commit the immutable graph**

```bash
git add src/regulatory_harvest/evaluation/attorney_baseline_artifacts.py tests/evaluation/test_attorney_baseline_artifacts.py
git commit -m "feat: seal and replay stable baselines"
```

---

### Task 6: Verified Gradeable Projection and Downstream Adapter

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_projection.py`
- Create: `tests/evaluation/test_attorney_baseline_projection.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_baseline_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: `load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1`, `BaselineInputV1`, `CanonicalBaselineV1`, and canonical JSON/SHA-256 helpers. It consumes no report, generation capsule, grader response, or Protocol 2.2 baseline/result type.
- Produces: `GradeableRequirementV1`, `GradeableContestedRequirementV1`, `BaselineGradeTargetBindingV1`, `GradeableBaselineProjectionV1`, `project_gradeable_baseline_v1(context: VerifiedBaselineContextV1) -> GradeableBaselineProjectionV1`, and `verify_gradeable_baseline_projection_v1(context: VerifiedBaselineContextV1, candidate: object) -> GradeableBaselineProjectionV1`.

- [ ] **Step 1: Write the grade-target RED tests**

Require exact lossless projection of sources, legal-input bindings, ordinary requirements, relationships, contested alternatives, importance metadata, and evaluation-rubric bytes. Prove that a report-only mutation cannot change projection bytes; every source, legal identity, semantic field, importance field, relationship, contested alternative, rubric byte, compiler contract, policy byte, baseline fingerprint, and provenance mutation changes or invalidates the grade target.

```python
def test_report_revision_reuses_exact_grade_target(verified_context, report_a, report_b) -> None:
    assert report_a != report_b
    left = project_gradeable_baseline_v1(verified_context)
    right = project_gradeable_baseline_v1(verified_context)
    assert canonical_json_bytes(left.model_dump(mode="json")) == canonical_json_bytes(
        right.model_dump(mode="json")
    )
    assert left.binding.grade_target_fingerprint == right.binding.grade_target_fingerprint


def test_projection_preserves_importance_contract(verified_context) -> None:
    projected = project_gradeable_baseline_v1(verified_context)
    assert [
        (item.requirement.importance, item.requirement.importance_basis, item.requirement.importance_rationale)
        for item in projected.requirements
    ] == [
        (item.importance, item.importance_basis, item.importance_rationale)
        for item in verified_context.baseline.requirements
    ]
```

Also reject a forged or invalid `VerifiedBaselineContextV1`, raw construction bypass, duplicate IDs/orders, source/quote/offset mismatch, nested extra keys, noncanonical rubric JSON, and any recursive report-bound field.

- [ ] **Step 2: Run the projection RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_projection.py -q
```

Expected: collection fails because `attorney_baseline_projection` does not exist and the grade-target types are absent.

- [ ] **Step 3: Define the exact typed grade target**

Add these strict immutable shapes to `attorney_baseline_models.py`:

```python
class GradeableRequirementV1(BaselineStrictModel):
    requirement: BaselineRequirementV1
    semantic_identity_fingerprint: Hash


class GradeableContestedRequirementV1(BaselineStrictModel):
    contested_requirement: ContestedBaselineRequirementV1
    reviewer_identity_fingerprint: Hash | None = None
    auditor_identity_fingerprint: Hash | None = None
    semantic_identity_fingerprint: Hash


class BaselineGradeTargetBindingV1(BaselineStrictModel):
    schema_version: Literal["baseline-grade-target-v1"]
    legal_input_fingerprint: Hash
    baseline_fingerprint: Hash
    source_record_fingerprint: Hash
    semantic_inventory_fingerprint: Hash
    evaluation_rubric_fingerprint: Hash
    importance_policy_fingerprint: Hash
    compiler_contract_fingerprint: Hash
    grade_target_fingerprint: Hash


class GradeableBaselineProjectionV1(BaselineStrictModel):
    schema_version: Literal["baseline-gradeable-projection-v1"]
    baseline_protocol_version: Literal["evaluation-baseline-v1"]
    binding: BaselineGradeTargetBindingV1
    baseline_input: BaselineInputV1
    requirements: tuple[GradeableRequirementV1, ...]
    relationships: tuple[BaselineRelationshipV1, ...]
    contested_requirements: tuple[GradeableContestedRequirementV1, ...]
    baseline_provenance: BaselineProvenanceV1
    projection_fingerprint: Hash
```

`BaselineInputV1` inside the projection supplies exact source IDs/text/metadata, source-record fingerprint, question, jurisdiction, as-of, requested authorities, explicit null or exact client-fact bytes, qualification root/receipt/readiness, compiler contract, evaluation-rubric version/bytes/fingerprint, and importance-policy version/bytes/fingerprint. No lossy V2.2 conversion is allowed.

- [ ] **Step 4: Implement semantic and grade-target fingerprints**

Hash each `BaselineRequirementV1` without an assigned lane/report; hash each contested record with both nullable alternatives and referee provenance; hash the ordered requirement/relationship/contest inventory as `semantic_inventory_fingerprint`. Then hash the complete eight-field fingerprint-excluded `BaselineGradeTargetBindingV1` projection as `grade_target_fingerprint`, and finally hash the full fingerprint-excluded `GradeableBaselineProjectionV1` as `projection_fingerprint`.

```python
def _grade_target_binding_v1(
    baseline_input: BaselineInputV1,
    baseline: CanonicalBaselineV1,
    semantic_inventory_fingerprint: str,
) -> BaselineGradeTargetBindingV1:
    raw = {
        "schema_version": "baseline-grade-target-v1",
        "legal_input_fingerprint": baseline_input.legal_input_fingerprint,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "source_record_fingerprint": baseline_input.source_record_fingerprint,
        "semantic_inventory_fingerprint": semantic_inventory_fingerprint,
        "evaluation_rubric_fingerprint": baseline_input.evaluation_rubric_fingerprint,
        "importance_policy_fingerprint": baseline_input.importance_policy_fingerprint,
        "compiler_contract_fingerprint": baseline_input.compiler_contract_fingerprint,
    }
    return BaselineGradeTargetBindingV1(
        **raw,
        grade_target_fingerprint=sha256_digest(canonical_json_bytes(raw)),
    )
```

- [ ] **Step 5: Implement the verified-context adapter**

```python
def project_gradeable_baseline_v1(
    context: VerifiedBaselineContextV1,
) -> GradeableBaselineProjectionV1:
    checked = _strict_verified_context_v1(context)
    _require_context_fingerprint_consistency_v1(checked)
    requirements = _gradeable_requirements_v1(checked.baseline.requirements)
    contested = _gradeable_contests_v1(checked.baseline.contested_requirements)
    semantic_fingerprint = _semantic_inventory_fingerprint_v1(
        requirements, checked.baseline.relationships, contested
    )
    binding = _grade_target_binding_v1(
        checked.baseline_input, checked.baseline, semantic_fingerprint
    )
    return _strict_projection_with_fingerprint_v1(
        checked, binding, requirements, contested
    )
```

`_strict_verified_context_v1()` must require `verification.valid is True` and matching verification/manifest/baseline/legal-input/root fingerprints. The public contract requires callers to obtain the context from `load_verified_baseline_run()`; possession of a structurally valid dataclass is not a new attestation mechanism. `verify_gradeable_baseline_projection_v1()` strictly rehydrates `candidate`, recomputes the projection from `context`, requires exact canonical bytes, and returns the recomputed value. It never accepts semantic similarity or inferred ID crosswalks.

- [ ] **Step 6: Define the downstream grading ownership boundary**

Document and test this exact contract: every fresh readiness grader request embeds `projection.binding`, the complete `projection`, exact report bytes/hash, and its readiness-owned lane ID; every accepted fresh grade embeds the same `grade_target_fingerprint`, `baseline_fingerprint`, report fingerprint, lane, and one disposition for every ordinary requirement and each contested alternative. Stable-baseline code supplies no report-bound request/result model and does not compute strict/readiness dispositions. Readiness code owns fresh grading schemas, two lanes, reconciliation, scoring, safety review, matrices, and tiers.

- [ ] **Step 7: Prove retained Protocol 2.2 isolation**

Add an import-graph assertion that `attorney_baseline_projection.py` does not import `attorney_v22_models`, `attorney_v22_compiler`, `attorney_v22_requests`, `attorney_v22_workflow`, or `attorney_v22_artifacts`. Snapshot retained Protocol 2.2 files and prove projection construction writes no file anywhere, especially inside a retained evaluation run.

- [ ] **Step 8: Run projection GREEN and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_projection.py tests/evaluation/test_attorney_baseline_models.py tests/evaluation/test_attorney_baseline_artifacts.py tests/evaluation/test_attorney_v22_artifacts.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_projection.py src/regulatory_harvest/evaluation/attorney_baseline_models.py tests/evaluation/test_attorney_baseline_projection.py src/regulatory_harvest/evaluation/__init__.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_baseline_projection.py src/regulatory_harvest/evaluation/attorney_baseline_models.py
```

Expected: all pass; no retained Protocol 2.2 byte changes.

- [ ] **Step 9: Commit the downstream grade target**

```bash
git add src/regulatory_harvest/evaluation/attorney_baseline_projection.py src/regulatory_harvest/evaluation/attorney_baseline_models.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_baseline_projection.py
git commit -m "feat: expose verified baseline grade targets"
```

---

### Task 7: Baseline Workflow and Full CLI Lifecycle

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_baseline_workflow.py`
- Create: `tests/evaluation/test_attorney_baseline_workflow.py`
- Create: `assets/attorney-evaluation-baseline-response.template.json`
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `scripts/attorney_eval_full.py`
- Modify: `scripts/harvest_skill.py`
- Modify: `tests/cli/test_eval_cli.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: Tasks 2-6 and existing CLI error/exit constants.
- Produces: `BaselineDraftEvaluatorV1`, `initialize_baseline_v1()`, `next_baseline_request_v1()`, `resume_baseline_v1()`, `guarded_submit_baseline_response_v1()`, `continue_baseline_v1()`, `BaselineDriverOutcomeV1`, and the five required `eval-baseline-*` commands.

- [ ] **Step 1: Write workflow and CLI RED tests**

Cover full role order, audit completeness, one referee per dispute, idempotent `next`, write-free invalid submission, one fresh repair, second-refusal pause, crash resume without duplicate accepted roles, correction initialization, all JSON/human status fields, no path/source leakage, and retained CLI snapshots.

```python
def test_baseline_commands_are_exact(parser) -> None:
    assert required_commands(parser) >= {
        "eval-baseline-init",
        "eval-baseline-next",
        "eval-baseline-submit-safe",
        "eval-baseline-status",
        "eval-baseline-verify",
    }


def test_second_mechanical_refusal_leaves_exact_request_pending(run: Path) -> None:
    before = snapshot_tree(run)
    result = drive_baseline_role(run, invalid_draft(), invalid_repair())
    assert result.exit_code == 6
    assert result.engine_paused is True
    assert pending_request_bytes(run) == pending_request_bytes_from(before)
    assert rejected_response_paths(run) == ()
```

- [ ] **Step 2: Run workflow/CLI RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_workflow.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py -q -k 'baseline'
```

Expected: baseline module and commands are absent.

- [ ] **Step 3: Implement recoverable workflow APIs**

```python
def initialize_baseline_v1(
    control_input_path: Path,
    output_dir: Path,
    *,
    nonce_hex: str,
    prior_baseline_path: Path | None = None,
    correction_path: Path | None = None,
) -> BaselineRunStateV1:
    baseline_input = build_baseline_input_v1(control_input_path)
    initial = _initial_baseline_transition_v1(
        baseline_input,
        nonce_hex=nonce_hex,
        prior_baseline_path=prior_baseline_path,
        correction_path=correction_path,
    )
    return initialize_baseline_storage_v1(output_dir, initial.manifest, initial.files)


def next_baseline_request_v1(run_dir: Path) -> BaselineEvaluatorRequestV1 | None:
    context = load_verified_baseline_context_v1(run_dir)
    return _pending_request_from_verified_context_v1(context)


def resume_baseline_v1(run_dir: Path) -> BaselineRunStateV1:
    return _state_from_manifest_v1(load_verified_baseline_context_v1(run_dir).manifest)


def guarded_submit_baseline_response_v1(
    run_dir: Path,
    payload: object,
    *,
    provider_name: str,
    model_name: str,
    judge_isolation: Literal["fresh_context", "scripted_fixture"],
) -> GuardedBaselineSubmissionResultV1:
    response = _controller_bound_response_v1(
        next_baseline_request_v1(run_dir),
        payload,
        provider_name=provider_name,
        model_name=model_name,
        judge_isolation=judge_isolation,
    )
    return _preflight_and_commit_baseline_response_v1(run_dir, response)
```

`initialize_baseline_v1()` first calls `build_baseline_input_v1(control_input_path)`, validates the ordinary-versus-correction argument pair, creates the first report-blind review request for an ordinary run or applies the verified correction for a correction run, and passes the exact initial files to `initialize_baseline_storage_v1()`. `continue_baseline_v1(run_dir, evaluator)` performs one initial draft and at most one fresh mechanical repair in one invocation; it returns `BaselineDriverOutcomeV1(engine_paused=True, exit_code=6, pending_request=<exact request>)` without changing the run after the second refusal.

Ordinary initialization must reject correction arguments. Correction initialization requires both a verified prior baseline and correction file, creates a new sibling run, and emits no role request. Role progression is review -> audit -> zero or more dispute-scoped referees -> sealed. Invalid strict payloads return only `BASELINE_EXTERNAL_RESPONSE_INVALID` and write nothing.

- [ ] **Step 4: Add the full CLI command family**

Use exact flags:

```text
eval-baseline-init --input CONTROL.json --run RUN --nonce-hex HEX64
                   [--prior-baseline PRIOR --correction CORRECTION.json]
eval-baseline-next --run RUN
eval-baseline-submit-safe --run RUN --response INNER.json
                          --provider-name NAME --model-name NAME
                          --judge-isolation fresh_context|scripted_fixture
eval-baseline-status --run RUN
eval-baseline-verify --run RUN
```

Map success/pending to exit `0`, invalid arguments/schema to `2`, integrity or secure-storage failure to `5`, and verified engine pause to `6`. Baseline creation has no legal-substance FAIL/INCONCLUSIVE result and must never reuse strict-evaluation exit `3` or `4`. JSON status contains `protocol_version`, `phase`, `pending_operation`, `request_fingerprint`, `legal_input_fingerprint`, optional `baseline_fingerprint`, manifest/root hash, and `engine_paused`; human output never says `PASS`.

- [ ] **Step 5: Add strict response template bytes**

Create a canonical sorted seven-key envelope with schema `evaluation-baseline-v1`, operation `baseline_source_review`, a 64-zero request fingerprint, nonblank illustrative provider/model, truthful illustrative `scripted_fixture`, and an empty schema-shaped payload. Serialize without a trailing newline and test it directly through the strict model.

- [ ] **Step 6: Preserve existing command dispatch and defaults**

Add baseline routing before the existing generic `eval-*` dispatch in both full runners so it cannot be misdetected as Protocol 1.3/2.x. Do not edit the existing `eval-init --protocol` choice/default, retained mutation rules, status/verify projections, or exit functions.

- [ ] **Step 7: Run workflow, CLI, and static GREEN gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_baseline_workflow.py tests/evaluation/test_attorney_baseline_artifacts.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_baseline_workflow.py src/regulatory_harvest/evaluation/attorney_cli.py scripts/attorney_eval_full.py scripts/harvest_skill.py tests/evaluation/test_attorney_baseline_workflow.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py
PYTHONPATH=src ../../.venv/bin/mypy src scripts/attorney_eval_full.py scripts/harvest_skill.py
```

Expected: all pass; `eval-init` still defaults to `2.1`.

- [ ] **Step 8: Commit the full lifecycle**

```bash
git add src/regulatory_harvest/evaluation/attorney_baseline_workflow.py src/regulatory_harvest/evaluation/attorney_cli.py scripts/attorney_eval_full.py scripts/harvest_skill.py assets/attorney-evaluation-baseline-response.template.json tests/evaluation/test_attorney_baseline_workflow.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py
git commit -m "feat: expose stable baseline lifecycle"
```

---

### Task 8: Standard-Library Portable Mirror and Exact Parity

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: exact wire, policy, request, compiler, artifact, gradeable-projection, workflow, CLI, and exit contracts from Tasks 1-7.
- Produces: isolated `python3 -I -S` baseline lifecycle and full/portable exact command/tree parity.

- [ ] **Step 1: Write portable differential RED tests**

For each lifecycle, run the same commands through `scripts/attorney_eval_full.py` and `python3 -I -S scripts/harvest_portable.py`; compare exit code, canonical stdout, stderr, request bytes, accepted response bytes, aggregates, canonical baseline, verification receipt, manifest, and complete tree.

Required rows: stable creation, zero disputes, semantic dispute, importance-only dispute, unresolved contest, gradeable projection and every semantic-identity mutation, report-only grade-target reuse, pause/resume at every operation, correction, every legal-input reuse refusal, invalid response, tamper/reseal, source/report-like swap, symlink/FIFO/hard-link/root replacement, rollback injection, and concurrent status/verify.

- [ ] **Step 2: Run portable RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py -q -k 'baseline_parity'
```

Expected: portable parser reports the new commands as invalid choices.

- [ ] **Step 3: Implement one bounded portable mirror**

Add one `# evaluation-baseline-v1 portable mirror` region in `scripts/attorney_eval_portable.py`. Mirror strict validation, deterministic compilation, and `GradeableBaselineProjectionV1` construction with standard-library types, but load and fingerprint the packaged `assets/evaluation-baseline-policy-v1.json`; do not copy the three definition strings into Python constants. Route the five commands from `scripts/harvest_portable.py` before retained evaluation routing.

- [ ] **Step 4: Prove exact policy and lifecycle parity**

Require the portable contract/policy, semantic-inventory, grade-target, and projection fingerprints to equal the full-runtime values. Add a mutation that changes one policy byte and prove both runtimes refuse verification with the same public-safe code. Add one unknown-extra-policy-key mutation so permissive portable parsing cannot drift from Pydantic. The portable test-only adapter accepts canonical verified baseline-run bytes and returns canonical `GradeableBaselineProjectionV1` bytes; it is not a public report-grading command.

- [ ] **Step 5: Run portable GREEN and isolated gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py tests/evaluation/test_attorney_baseline_artifacts.py tests/evaluation/test_attorney_baseline_projection.py -q
PYTHONPATH=src ../../.venv/bin/ruff check scripts/attorney_eval_portable.py scripts/harvest_portable.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py
PYTHONPATH=src ../../.venv/bin/mypy src
python3 -I -S scripts/harvest_portable.py eval-baseline-init --help
python3 -I -S scripts/harvest_portable.py eval-baseline-verify --help
```

Expected: all pass; isolated help imports no installed `regulatory_harvest`, Pydantic, or site packages.

- [ ] **Step 6: Audit portable duplication and commit**

Record the single marker, baseline mirror line count, duplicate `_baseline_` definitions, policy-load sites, and exact diff. Remove duplicate command branches or independently defined policy values.

```bash
git add scripts/attorney_eval_portable.py scripts/harvest_portable.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py
git commit -m "feat: mirror stable baselines portably"
```

---

### Task 9: Package Guards, Documentation, and Deterministic Public Fixtures

**Files:**
- Create: `tests/fixtures/attorney-eval-baseline/qualification/qualification-case.json`
- Create: `tests/fixtures/attorney-eval-baseline/qualification/admission-request.json`
- Create: `tests/fixtures/attorney-eval-baseline/qualification/admission-response.json`
- Create: `tests/fixtures/attorney-eval-baseline/qualification/qualification-receipt.json`
- Create: `tests/fixtures/attorney-eval-baseline/qualification/qualification-manifest.json`
- Create: `tests/fixtures/attorney-eval-baseline/stable/control-input.json`
- Create: `tests/fixtures/attorney-eval-baseline/stable/client-facts.txt`
- Create: `tests/fixtures/attorney-eval-baseline/stable/responses/scripted-responses.json`
- Create: `tests/fixtures/attorney-eval-baseline/pause-resume/control-input.json`
- Create: `tests/fixtures/attorney-eval-baseline/pause-resume/responses/initial.json`
- Create: `tests/fixtures/attorney-eval-baseline/pause-resume/responses/resume.json`
- Create: `tests/fixtures/attorney-eval-baseline/correction/correction.json`
- Modify: `scripts/skill-package-files.txt`
- Modify: `scripts/build_skill.py`
- Modify: `README.md`
- Modify: `SKILL.md`
- Modify: `docs/evaluation.md`
- Modify: `references/attorney-evaluation.md`
- Modify: `references/security-and-privacy.md`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/skill/test_skill_package.py`
- Modify: `tests/fixtures/FIXTURE_LICENSES.md`

**Interfaces:**
- Consumes: complete full and portable baseline implementations from Tasks 1-8.
- Produces: package-complete runtime/assets, public deterministic lifecycle fixtures, and baseline-specific operator/security documentation.

- [ ] **Step 1: Write package/docs/fixture RED tests**

Require every new module and asset exactly once in `scripts/skill-package-files.txt`, dedicated missing-input builder failures, canonical/no-newline templates, fixture license coverage, no private path/content markers, and headings for identity, importance definitions, report blindness, gradeable projection/fresh revision grading, reuse/refusal, correction, resume, and attorney-review limits.

- [ ] **Step 2: Run package RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py -q -k 'baseline or package_manifest'
```

Expected: package guards fail because baseline modules/assets are absent from the manifest and archive.

- [ ] **Step 3: Add direct public fixtures**

The stable fixture must be fictional and exercise all three importance levels, semantic and importance disagreements, accepted reviewer/auditor referee outcomes, substantive unresolved, relationships, explicit client facts, terminal replay, and reuse across two synthetic report hashes that never enter baseline bytes. The pause fixture must stop after a second mechanical refusal and resume the exact request without duplicating an accepted role. The correction fixture must create a new sibling tree and preserve the prior tree hash.

- [ ] **Step 4: Update operator and security documentation**

Document the five commands as attorney-hidden mechanics, exact reuse boundary, typed `GradeableBaselineProjectionV1` adapter, readiness-owned fresh grading for every later report revision, importance definitions, complete importance audit, correction approval, exit `0/2/5/6`, private-work-product status of source and baseline artifacts, no-upload/no-web-search rule for private material, qualified-attorney review requirement, and explicit experimental status. State that a verified baseline proves local integrity/replay, not legal correctness, completeness, currentness, isolation truth, attorney approval authenticity, or report quality. Explicitly prohibit regenerating source roles or demanding a Protocol 2.2 baseline equality check for a report-only revision.

- [ ] **Step 5: Add package entries and guards**

Add the seven new full-runtime files (`models`, `input`, `requests`, `compiler`, `artifacts`, `projection`, `workflow`), three assets, updated docs, and fixture license. Make `scripts/build_skill.py` fail closed when any is absent, duplicated, noncanonical, or omitted from the archive. Do not package tests or private control data.

- [ ] **Step 6: Run package/docs/fixture GREEN gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py tests/scripts/test_harvest_skill.py tests/scripts/test_attorney_eval_portable.py -q
PYTHONPATH=src ../../.venv/bin/ruff check scripts/build_skill.py tests/scripts/test_build_skill.py tests/skill/test_skill_package.py
PYTHONPATH=src ../../.venv/bin/mypy src
git diff --check
```

Expected: all pass.

- [ ] **Step 7: Build and inspect one local package**

```bash
../../.venv/bin/python scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
../../.venv/bin/python scripts/audit_release.py --archive dist/regulatory-harvest-skill.zip --json
python3 -I -S scripts/harvest_portable.py eval-baseline-init --help
```

Require sorted unique archive members, exact manifest membership, archive-member/Git-blob equality, clean extraction, no private markers, and full plus isolated portable help.

- [ ] **Step 8: Commit package, fixtures, and docs**

```bash
git add tests/fixtures/attorney-eval-baseline tests/fixtures/FIXTURE_LICENSES.md scripts/skill-package-files.txt scripts/build_skill.py README.md SKILL.md docs/evaluation.md references/attorney-evaluation.md references/security-and-privacy.md tests/scripts/test_build_skill.py tests/skill/test_skill_package.py
git commit -m "docs: package stable evaluation baselines"
```

---

### Task 10: Stress, Compatibility, Security, and Release-Candidate Gates

**Files:**
- Create: `tests/evaluation/test_attorney_baseline_stress.py`
- Create: `tests/evaluation/test_attorney_baseline_compatibility.py`
- Create: `tests/evaluation/test_attorney_baseline_security.py`
- Modify only when a traced RED requires a test-first correction within `evaluation-baseline-v1` scope.
- Create ignored evidence: `.superpowers/sdd/2026-08-24-stable-evaluation-baseline/task-10-report.md`

**Interfaces:**
- Consumes: exact implementation and commits from Tasks 1-9 plus retained tag `v0.1.0-beta.8` at `c958493c0053b9f1a4c5779569eac7025299a550`.
- Produces: public stress/parity/compatibility/security/build evidence and an independent-review verdict. It does not publish or run a private matter.

- [ ] **Step 1: Write deterministic stress RED tests**

Use at least 100 seeded public lifecycles. Vary zero/one/five/six/128/>128 fragments, up to 640/>640 items, every importance combination, audit corrections, all referee outcomes, null/empty/present client facts, corrections, invalid responses, crash points, concurrent operations, and full/portable execution.

```python
@pytest.mark.parametrize("seed", range(100))
def test_baseline_lifecycle_is_deterministic_and_report_blind(seed: int, tmp_path: Path) -> None:
    full, portable = run_seeded_baseline_lifecycle(seed, tmp_path)
    assert full.transcript == portable.transcript
    assert full.tree_bytes == portable.tree_bytes
    assert full.report_mutation_baseline_fingerprint == full.baseline_fingerprint
    assert full.report_mutation_grade_target_fingerprint == full.grade_target_fingerprint
    assert not recursive_contains_report_field(full.tree_json)
```

- [ ] **Step 2: Write retained-byte/default compatibility RED tests**

Snapshot the four retained response templates at these beta.8 SHA-256 values:

```text
774af5d3f5a2126c04190c3559e2cad9ba61ee677b0f85b67e0825ce97ed38d7  assets/attorney-evaluation-response.template.json
6196f39634dc550fb03804ca3a550746f255981ff2103c11247f7fbb92cea00f  assets/attorney-evaluation-v2-response.template.json
f02dc3c539816af51f6ab0fa709844a22af1041528a43018488b631aacd44955  assets/attorney-evaluation-v21-response.template.json
f62f2215d79cb417234939ab33f3b9ab13efc39d211daade273f9e3e8ca1a949  assets/attorney-evaluation-v22-response.template.json
```

Compare every tracked retained fixture under `tests/fixtures/attorney-eval`, `attorney-eval-v2`, `attorney-eval-v21`, and `attorney-eval-v22` to `git show v0.1.0-beta.8:<path>`. Replay retained status/verify/mutation suites in full and portable runners, and assert `eval-init` still defaults to `2.1` with identical stdout/stderr/exit behavior.

- [ ] **Step 3: Write security/adversarial RED tests**

Cover path escapes, absolute paths in control files, symlink aliases, FIFO/device/hard-link inputs, root replacement, source/control instruction injection, secret-like values in public status, report-like keys at every nested input and projection level, forged qualification readiness, source byte swaps, null/empty fact confusion, cross-baseline/correction/projection swaps, semantic-inventory and grade-target reseals, manifest reseal, policy replacement, rejected-response persistence, and unsafe diagnostics.

- [ ] **Step 4: Run focused baseline gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest \
  tests/evaluation/test_attorney_baseline_models.py \
  tests/evaluation/test_attorney_baseline_input.py \
  tests/evaluation/test_attorney_baseline_requests.py \
  tests/evaluation/test_attorney_baseline_compiler.py \
  tests/evaluation/test_attorney_baseline_artifacts.py \
  tests/evaluation/test_attorney_baseline_projection.py \
  tests/evaluation/test_attorney_baseline_workflow.py \
  tests/evaluation/test_attorney_baseline_stress.py \
  tests/evaluation/test_attorney_baseline_compatibility.py \
  tests/evaluation/test_attorney_baseline_security.py \
  tests/cli/test_eval_cli.py \
  tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py -q
```

Expected: all pass with exact full/portable tree parity and no report bytes in any baseline request or identity.

- [ ] **Step 5: Run the complete repository gate**

```bash
PYTHONPATH=src ../../.venv/bin/pytest -q
PYTHONPATH=src ../../.venv/bin/ruff check .
PYTHONPATH=src ../../.venv/bin/mypy src
git diff --check
git status --short
```

Expected: all tests and static checks pass. Commit the three stress/gate tests, then require a clean tracked worktree.

- [ ] **Step 6: Commit the public gate tests**

```bash
git add tests/evaluation/test_attorney_baseline_stress.py tests/evaluation/test_attorney_baseline_compatibility.py tests/evaluation/test_attorney_baseline_security.py
git commit -m "test: stress stable evaluation baselines"
```

- [ ] **Step 7: Build twice from the exact detached commit**

Use two clean `git clone --no-local` checkouts of the exact commit. In each, run `uv sync --frozen --all-extras --dev`, the complete gate, `uv build`, and `python scripts/build_skill.py --output dist/regulatory-harvest-skill.zip`. Require identical skill-archive SHA-256/size/member order, wheel/sdist member parity, exact Git-blob equality, clean extraction, full CLI help, and isolated portable help.

- [ ] **Step 8: Run privacy, history, and clean-room audits**

Run `scripts/audit_release.py` against both archives and inspect the complete reachable history and ignored/untracked surfaces for credentials, private names/facts/quotes, absolute user paths, private evaluation roots, generated responses, source text, report text, matrices, archives, and metadata. Pass only approved opaque owner-marker arguments. Require zero automated findings and record manual review boundaries.

- [ ] **Step 9: Obtain independent review**

Give the reviewer the approved spec, this plan, exact diff, task reports, focused/full outputs, compatibility snapshots, full/portable differential evidence, build hashes, archive inventories, and privacy/history audit outputs. Any Critical or Important finding returns to the owning task with a new RED, fresh commit, and rerun of Steps 4-8.

- [ ] **Step 10: Record the public decision without publishing**

Write exactly one result to the ignored report:

- `PUBLIC BASELINE GATE PASSED: DELIVERY-READINESS IMPLEMENTATION MAY CONSUME THIS INTERFACE`; or
- `PUBLIC BASELINE GATE NOT PASSED: EVALUATION-BASELINE-V1 REMAINS EXPERIMENTAL`.

Do not push, merge, tag, release, publish, run private matter data, or change the Protocol 2.1 default.

---

## Plan Completion Gate

- [ ] Every approved stable-baseline requirement maps to a task: operational importance definitions/rationales (Tasks 1, 3, 4), source review/audit/referee (Tasks 3, 4, 7), canonical report-independent identity and reuse refusal (Task 2), immutable artifacts/replay/resume (Tasks 5, 7), exact gradeable projection for readiness-owned fresh report grading (Task 6), append-only corrections (Tasks 4-7), full CLI (Task 7), portable parity (Task 8), and package/docs/fixtures/stress/compatibility/security gates (Tasks 9-10).
- [ ] `load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1` remains unchanged with context fields `manifest`, `baseline_input`, `baseline`, and `verification`; `project_gradeable_baseline_v1(context) -> GradeableBaselineProjectionV1` is the additive delivery-readiness grading handoff.
- [ ] A report-only revision preserves `legal_input_fingerprint`, `baseline_fingerprint`, `semantic_inventory_fingerprint`, and `grade_target_fingerprint`, then receives two fresh readiness-owned grades bound to that grade target; neither baseline regeneration nor Protocol 2.2 baseline equality is required.
- [ ] Any semantic/source/rubric/policy/compiler/correction change changes or invalidates `grade_target_fingerprint`, and exact `verify_gradeable_baseline_projection_v1()` validation precedes every downstream grading request.
- [ ] Every task begins from its exact parent commit, uses RED before production changes, records expected failure and observed GREEN output, receives independent review, and ends in one reviewable commit.
- [ ] Any interface change updates this plan and the separate delivery-readiness plan before downstream implementation.
- [ ] No retained 1.3/2.0/2.1/2.2 byte, default, output, exit, artifact, fixture, or replay path changes.
- [ ] The approved design and both implementation plans travel together during execution.
