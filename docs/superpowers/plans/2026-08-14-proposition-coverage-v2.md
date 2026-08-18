# Proposition Coverage V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require every new matter to reconcile complete source review into atomic, source-supported legal propositions and visibly preserve material relationships without forcing a database-shaped attorney memo.

**Architecture:** Keep the v1 contract and replay branch immutable. Add a separate v2 draft model and `atomic_coverage.py` reconciler with three layers: source and lead review, atomic rule graph, and exact-evidence/visible-brief binding. Dispatch by the dossier contract version and mirror the complete v2 implementation in the standard-library portable runner.

**Tech Stack:** Python 3.11+, Pydantic v2, canonical JSON/SHA-256, existing source-unit and provision-lead inventories, existing claim/citation and attorney-brief models, pytest, Ruff, mypy, standalone standard-library portable runtime.

## Global Constraints

- New prepares default to `proposition-coverage-v2`; v1 matters remain parseable and replay byte-identically.
- Deterministic code validates structure, exact evidence, relationships, and visibility; it does not decide substantive legal meaning or materiality.
- Every source unit and provision lead must receive an explicit disposition, including nonpriority leads and nonmaterial navigation.
- Genuine `gap`, `not_present`, and reasoned `not_material` outcomes remain valid; the engine may not require invention.
- Critical and material atoms must reach visible legal analysis. Related atoms may share one paragraph, list item, or table row.
- `Key Requirements` remains law-facing and `Implementation Workplan` remains application-facing.
- Full and portable runtimes must produce byte-identical reviews, diagnostics, counts, hashes, receipt fields, and completion decisions.
- Public code and fixtures may use only generic logic and synthetic/public-safe text. No private evaluation material may enter Git.
- Do not publish, push, open a pull request, or change repository visibility.

---

## File structure

- `src/regulatory_harvest/analysis/atomic_coverage.py`: v2 unit/lead/atom/relationship/evidence/visibility reconciliation.
- `src/regulatory_harvest/analysis/coverage_common.py`: immutable source-target, claim, gap, and brief-binding indexes shared by v1 and v2.
- `src/regulatory_harvest/analysis/drafts.py`: strict v2 authoring models and analysis-draft fields.
- `src/regulatory_harvest/models/enums.py`: v2 review, materiality, and relationship vocabularies.
- `src/regulatory_harvest/models/brief.py`: visible atom and relationship bindings on paragraphs, items, and rows.
- `src/regulatory_harvest/analysis/proposition_coverage.py`: unchanged v1 evaluation plus version dispatcher integration.
- `scripts/harvest_skill.py`: v2 prepare/finalize selection and coverage-review schema routing.
- `scripts/harvest_portable.py`: complete dependency-free v2 parser and reconciler.
- `assets/analysis-draft.template.json`: strict fictional v2 example.
- `src/regulatory_harvest/analysis/prompts/build-v1.md`, `references/draft-schema.md`, `references/research-protocol.md`, and `SKILL.md`: authoring and repair workflow.
- `tests/analysis/test_atomic_coverage.py`: v2 contract, closure, relationship, and failure tests.
- `tests/analysis/test_drafts.py`: strict parser and v1/v2 compatibility.
- `tests/analysis/test_proposition_coverage.py`: v1 byte/shape immutability.
- `tests/scripts/test_harvest_portable.py`: full/portable raw and finalized byte parity.
- `tests/e2e/test_skill_flow.py`: natural attorney report from a complete v2 draft.
- `tests/scripts/test_build_skill.py` and `scripts/skill-package-files.txt`: package inclusion and clean-build behavior.

### Task 1: V2 draft and brief-binding contract

**Files:**
- Modify: `src/regulatory_harvest/models/enums.py`
- Modify: `src/regulatory_harvest/models/brief.py`
- Modify: `src/regulatory_harvest/analysis/drafts.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`
- Test: `tests/analysis/test_drafts.py`
- Test: `tests/analysis/test_report.py`

**Interfaces:**
- Produces: `UnitDimensionDisposition`, `LeadDispositionV2`, `AtomMateriality`, and `AtomRelationshipType`.
- Produces: `DraftUnitReview`, `DraftLeadDispositionV2`, `DraftRuleAtom`, `DraftRuleRelationship`, and strict nested element models.
- Produces: `atom_ids` and `relationship_ids` on visible brief blocks, items, and table rows.

- [ ] **Step 1: Write strict-model RED tests**

Test every valid disposition and invalid cardinality, v1/v2 version acceptance, duplicate IDs, validation-bypassing values, and brief bindings:

```python
def test_v2_draft_accepts_one_complete_atomic_rule_graph() -> None:
    draft = AnalysisDraft.model_validate(v2_draft_payload())
    assert draft.coverage_contract_version == "proposition-coverage-v2"
    assert draft.unit_reviews[0].unit_id == "unit-1"
    assert draft.rule_atoms[0].atom_id == "atom-duty"
    assert draft.rule_relationships[0].relation_type.value == "exception_to"


@pytest.mark.parametrize(
    "mutation",
    [
        "mapped_without_atom",
        "gap_without_code",
        "not_material_without_rationale",
        "stated_element_without_claim",
        "not_established_element_without_gap",
        "self_relationship",
        "duplicate_atom_id",
    ],
)
def test_v2_draft_rejects_invalid_cardinality(mutation: str) -> None:
    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(mutate(v2_draft_payload(), mutation))
```

Assert an unchanged v1 payload still produces the same model dump as before Task 1.

- [ ] **Step 2: Run parser tests and capture RED**

```bash
.venv/bin/pytest tests/analysis/test_drafts.py tests/analysis/test_report.py -q -k 'v2 or atom or relationship'
```

Expected: failures because v2 is rejected and new fields do not exist.

- [ ] **Step 3: Add controlled vocabularies**

```python
class UnitDimensionDisposition(StrEnum):
    MAPPED = "mapped"
    NOT_PRESENT = "not_present"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class LeadDispositionV2(StrEnum):
    MAPPED = "mapped"
    GAP = "gap"
    NOT_MATERIAL = "not_material"


class AtomMateriality(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class AtomRelationshipType(StrEnum):
    QUALIFIES = "qualifies"
    EXCEPTION_TO = "exception_to"
    DEADLINE_FOR = "deadline_for"
    ENFORCES = "enforces"
    TRIGGERED_BY = "triggered_by"
    CONSEQUENCE_OF = "consequence_of"
    APPEALS_FROM = "appeals_from"
    DEFINES = "defines"
```

- [ ] **Step 4: Add strict nested authoring models**

Use fixed source-review fields so all nine dimensions are present:

```python
class DraftDimensionReview(StrictModel):
    disposition: UnitDimensionDisposition
    atom_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)
    rationale: str | None = None


class DraftUnitReviewDimensions(StrictModel):
    authority_status_timing: DraftDimensionReview
    actors_scope_activities: DraftDimensionReview
    definitions_categories: DraftDimensionReview
    duties_rights_prohibitions: DraftDimensionReview
    triggers_thresholds: DraftDimensionReview
    conditions_exceptions_defenses: DraftDimensionReview
    deadlines_transitions: DraftDimensionReview
    enforcement_remedies_consequences: DraftDimensionReview
    cross_references_dependencies: DraftDimensionReview


class DraftUnitReview(StrictModel):
    unit_id: str
    dimensions: DraftUnitReviewDimensions
```

`mapped` requires atoms and forbids gaps/rationale; `gap` requires gap codes and forbids atoms; `not_present` permits no payload; `not_material` requires only a rationale.

Add `DraftLeadDispositionV2` with `lead_id`, disposition, atom IDs, gap codes, and rationale under analogous cardinality.

- [ ] **Step 5: Add atomic element, atom, and relationship models**

```python
class DraftAtomElement(StrictModel):
    status: CoverageElementStatus
    text: str | None = None
    claim_ids: list[str] = Field(default_factory=list)
    gap_codes: list[str] = Field(default_factory=list)


class DraftRuleAtomElements(StrictModel):
    actor: DraftAtomElement
    modality: DraftAtomElement
    operative_action: DraftAtomElement
    object: DraftAtomElement
    trigger: DraftAtomElement
    threshold: DraftAtomElement
    condition: DraftAtomElement
    exception: DraftAtomElement
    timing: DraftAtomElement
    authority: DraftAtomElement
    route: DraftAtomElement
    consequence: DraftAtomElement
    defined_term: DraftAtomElement
    defined_meaning: DraftAtomElement


class DraftRuleAtom(StrictModel):
    atom_id: str
    unit_ids: list[str] = Field(default_factory=list)
    lead_ids: list[str] = Field(default_factory=list)
    category: IssueCategory
    proposition_type: PropositionType
    materiality: AtomMateriality
    elements: DraftRuleAtomElements
    omission_rationale: str


class DraftRuleRelationship(StrictModel):
    relationship_id: str
    relation_type: AtomRelationshipType
    source_atom_id: str
    target_atom_id: str
    claim_ids: list[str] = Field(min_length=1)
```

`STATED` requires text and claim IDs; `NOT_ESTABLISHED` requires gap codes; `NOT_APPLICABLE` permits none. An atom requires a source unit or lead target, a controlled `IssueCategory`, and a nonblank omission-consequence rationale. The atom's claim set is the sorted union of its stated elements' claim IDs rather than a second author-controlled field. Relationships reject self-links.

- [ ] **Step 6: Add versioned fields and visible bindings**

Extend `AnalysisDraft` with default-empty `unit_reviews`, `lead_dispositions_v2`, `rule_atoms`, and `rule_relationships`. Accept exactly v1, v2, or null. Add sorted unique `atom_ids` and `relationship_ids` to `BriefBlock`, `BriefItem`, and `BriefTableRow`; list/table container blocks continue to keep evidence on individual items/rows.

- [ ] **Step 7: Run parser and report-model tests**

```bash
.venv/bin/pytest tests/analysis/test_drafts.py tests/analysis/test_report.py -q
.venv/bin/ruff check src/regulatory_harvest/models src/regulatory_harvest/analysis/drafts.py tests/analysis/test_drafts.py
.venv/bin/mypy src/regulatory_harvest/models src/regulatory_harvest/analysis/drafts.py
```

- [ ] **Step 8: Commit Task 1**

```bash
git add src/regulatory_harvest/models/enums.py src/regulatory_harvest/models/brief.py src/regulatory_harvest/analysis/drafts.py src/regulatory_harvest/analysis/__init__.py tests/analysis/test_drafts.py tests/analysis/test_report.py
git commit -m "feat: add atomic coverage draft contract"
```

### Task 2: Shared immutable coverage indexes

**Files:**
- Create: `src/regulatory_harvest/analysis/coverage_common.py`
- Modify: `src/regulatory_harvest/analysis/proposition_coverage.py`
- Test: `tests/analysis/test_proposition_coverage.py`
- Create: `tests/analysis/test_coverage_common.py`

**Interfaces:**
- Produces: immutable `_Target`, `_CitationSpan`, `_ClaimRecord`, `target_indexes`, `claim_index`, `gap_index`, and `brief_binding_index` helpers.
- Consumes: existing v1 inventories, built findings, exact citations, gaps, and `AttorneyBrief`.
- Guarantees: v1 review objects and hashes are byte-identical before and after extraction.

- [ ] **Step 1: Freeze representative v1 outputs in a RED/characterization test**

Construct covered, gap, not-material, multi-source, malformed-row, and mixed brief-shape fixtures. Hash canonical v1 outputs and assert the exact existing values in the test. Also assert `evaluate_coverage_closure` input objects are unmodified.

- [ ] **Step 2: Run the characterization set before refactoring**

```bash
.venv/bin/pytest tests/analysis/test_proposition_coverage.py -q -k 'outputs_issues_and_composite_hash or brief_locations or multi_source or malformed'
```

Expected: PASS. Save the exact hashes in the test before moving helpers.

- [ ] **Step 3: Extract pure shared helpers**

Move only source indexing, target parsing, claim/citation indexing, gap indexing, and brief traversal. Use frozen dataclasses and return new mappings/lists; never mutate the dossier or draft. Expose exact signatures `brief_binding_index(brief: AttorneyBrief | None) -> BriefBindingIndex` and `claim_index(draft: AnalysisDraft, sources: Sequence[SourceRecord]) -> tuple[dict[str, ClaimRecord], list[dict[str, object]]]`.

Keep v1 messages, sort keys, and output construction in `proposition_coverage.py` unchanged.

- [ ] **Step 4: Add common-helper boundary and no-mutation tests**

Test half-open overlap, duplicate source/claim/gap IDs, all brief shapes, non-legal-analysis exclusion, and deep input equality before/after calls.

- [ ] **Step 5: Run exact v1 regression and static checks**

```bash
.venv/bin/pytest tests/analysis/test_coverage_common.py tests/analysis/test_proposition_coverage.py -q
.venv/bin/ruff check src/regulatory_harvest/analysis/coverage_common.py src/regulatory_harvest/analysis/proposition_coverage.py tests/analysis
.venv/bin/mypy src/regulatory_harvest/analysis
```

- [ ] **Step 6: Commit Task 2**

```bash
git add src/regulatory_harvest/analysis/coverage_common.py src/regulatory_harvest/analysis/proposition_coverage.py tests/analysis/test_coverage_common.py tests/analysis/test_proposition_coverage.py
git commit -m "refactor: share immutable coverage indexes"
```

### Task 3: Source-unit and provision-lead review closure

**Files:**
- Create: `src/regulatory_harvest/analysis/atomic_coverage.py`
- Create: `tests/analysis/test_atomic_coverage.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`

**Interfaces:**
- Produces: `evaluate_atomic_target_review(source_unit_inventory, evidence_inventory, draft, sources) -> dict[str, object]`.
- Consumes: Task 1 v2 models and Task 2 target/gap indexes.
- Produces bounded diagnostics: `ATOMIC_UNIT_REVIEW_UNRESOLVED`, `ATOMIC_LEAD_REVIEW_UNRESOLVED`, `ATOMIC_TARGET_UNKNOWN`, `ATOMIC_REVIEW_INVALID`, and `ATOMIC_GAP_INVALID`.

- [ ] **Step 1: Write closure RED tests**

Cover omitted units, omitted nonpriority leads, all nine dimensions, target reciprocity, gaps, nonmaterial navigation, multi-source targets, and malformed raw objects:

```python
def test_every_unit_dimension_and_every_lead_must_close() -> None:
    review = evaluate_atomic_target_review(units(), leads(), incomplete_v2_draft(), sources())
    assert review["valid"] is False
    assert {issue["code"] for issue in review["issues"]} == {
        "ATOMIC_UNIT_REVIEW_UNRESOLVED",
        "ATOMIC_LEAD_REVIEW_UNRESOLVED",
    }


def test_mapped_review_requires_reciprocal_atom_target() -> None:
    draft = v2_draft_with_unit_mapping(atom_targets_other_unit=True)
    review = evaluate_atomic_target_review(units(), leads(), draft, sources())
    assert issue_codes(review) == ["ATOMIC_REVIEW_INVALID"]
```

- [ ] **Step 2: Run the new suite and capture RED**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py -q -k 'unit or lead or target_review'
```

Expected: import failure because `atomic_coverage.py` does not exist.

- [ ] **Step 3: Implement fail-closed target parsing**

Revalidate typed rows from model dumps inside one exception boundary before accessing fields. Validate inventory version, counts, exact source slices, unique IDs, and known sources by reusing Task 2 helpers. A malformed row yields one bounded issue and does not prevent a canonical result or hash.

- [ ] **Step 4: Reconcile all unit dimensions**

For each prepared unit, require exactly one `DraftUnitReview`; for each of its nine dimensions:

- `mapped`: every atom exists and reciprocally names the unit;
- `gap`: every gap exists and names the unit's source;
- `not_present`: no atoms, gaps, or rationale;
- `not_material`: nonblank concrete rationale and no atoms or gaps.

Unknown or duplicate units fail closed. Output one canonical result per prepared unit, ordered by source and offsets.

- [ ] **Step 5: Reconcile every provision lead**

Require exactly one lead disposition for every inventory lead, including nonpriority leads. `mapped` atoms reciprocally name the lead; `gap` source/category bindings match; `not_material` includes a concrete rationale. Output source-order canonical results.

- [ ] **Step 6: Run focused and adversarial tests**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py -q -k 'unit or lead or malformed or target_review'
```

- [ ] **Step 7: Commit Task 3**

```bash
git add src/regulatory_harvest/analysis/atomic_coverage.py src/regulatory_harvest/analysis/__init__.py tests/analysis/test_atomic_coverage.py
git commit -m "feat: close atomic source review targets"
```

### Task 4: Atomic rule and relationship validation

**Files:**
- Modify: `src/regulatory_harvest/analysis/atomic_coverage.py`
- Modify: `tests/analysis/test_atomic_coverage.py`

**Interfaces:**
- Produces: `evaluate_rule_graph(draft: AnalysisDraft) -> dict[str, object]`.
- Produces bounded diagnostics: `ATOMIC_RULE_INVALID`, `ATOMIC_REQUIRED_ELEMENT_MISSING`, `ATOMIC_RELATIONSHIP_UNKNOWN`, `ATOMIC_RELATIONSHIP_INVALID`, and `ATOMIC_RELATIONSHIP_REQUIRED`.

- [ ] **Step 1: Add category and relationship RED tests**

Use a table whose valid minimum and required relationship are explicit:

```python
CASES = (
    ("status", ("object",), None),
    ("definition", ("defined_term", "defined_meaning"), None),
    ("scope", ("actor", "object"), None),
    ("duty", ("actor", "modality", "operative_action", "object"), None),
    ("prohibition", ("actor", "modality", "operative_action", "object"), None),
    ("right", ("actor", "modality", "operative_action", "object"), None),
    ("exception", ("exception",), "exception_to"),
    ("deadline", ("timing",), "deadline_for"),
    ("enforcement_trigger", ("trigger",), "triggered_by"),
    ("enforcement_route", ("authority", "route"), "enforces"),
    ("remedy", ("consequence",), ("triggered_by", "consequence_of")),
    ("penalty", ("consequence",), ("triggered_by", "consequence_of")),
    ("appeal", ("route",), "appeals_from"),
    ("implementation", ("operative_action", "object"), None),
    ("other", ("object",), None),
)
```

The existing `PropositionType` values include both `enforcement_trigger` and `enforcement_route`. An enforcement trigger requires a stated trigger and a `triggered_by` link to the governed duty or prohibition. An enforcement route requires stated authority and route plus an `enforces` link to the governed rule. A remedy or penalty requires a stated consequence and either `triggered_by` to a separate enforcement-trigger atom or `consequence_of` to the violated duty or prohibition. A definition may stand alone; `defines` is validated when the author declares it but is not mandatory for every definition.

Test unknown endpoints, self-links, invalid direction/category pairs, duplicate relationship IDs, missing omission rationales, and prohibited cycles among `exception_to`, `deadline_for`, `triggered_by`, `consequence_of`, and `appeals_from`.

- [ ] **Step 2: Run relationship tests and capture RED**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py -q -k 'rule_graph or relationship or required_element'
```

- [ ] **Step 3: Implement strict atom snapshots and category rules**

Round-trip every atom and relationship through its Pydantic model before sorting, counting, hashing, or dereferencing. Validate unique IDs and atom target presence. Use a fixed mapping from proposition type to required stated elements.

- [ ] **Step 4: Implement typed relationship validation**

Require both endpoints, supported relation direction, and relation-specific categories. For example, `exception_to` sources an exception atom and targets a duty, prohibition, right, scope, or requirement-like atom; `deadline_for` sources a deadline and targets the governed rule; `enforces` sources an enforcement route and targets the regulated rule; and consequence atoms use the trigger/consequence alternatives defined in Step 1.

Use depth-first cycle detection over only relation types that cannot be recursively self-dependent. `qualifies` and `defines` may form cross-reference graphs but may not self-link.

- [ ] **Step 5: Add independent-action adversarial cases**

The deterministic engine cannot parse legal semantics, so lock the enforceable boundary: one atom has one proposition type, and any applicable `operative_action` is one scalar element. Add tests showing two atoms from one unit are valid and an action-bearing atom cannot use list-valued or duplicate operative actions. Do not require an operative action for definitions, deadlines, status, or other types whose fixed table does not name it, and do not add English-only conjunction rejection.

- [ ] **Step 6: Run the complete rule-graph suite**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py -q
```

- [ ] **Step 7: Commit Task 4**

```bash
git add src/regulatory_harvest/analysis/atomic_coverage.py tests/analysis/test_atomic_coverage.py
git commit -m "feat: validate atomic legal relationships"
```

### Task 5: Exact evidence, visible atoms, and composite v2 review

**Files:**
- Modify: `src/regulatory_harvest/analysis/atomic_coverage.py`
- Modify: `src/regulatory_harvest/analysis/proposition_coverage.py`
- Modify: `src/regulatory_harvest/analysis/__init__.py`
- Modify: `tests/analysis/test_atomic_coverage.py`
- Modify: `tests/analysis/test_proposition_coverage.py`

**Interfaces:**
- Produces: `evaluate_atomic_coverage(source_unit_inventory: Mapping[str, object], evidence_inventory: Mapping[str, object], draft: AnalysisDraft, sources: Sequence[SourceRecord]) -> dict[str, object]` and the existing version-dispatched `evaluate_coverage_closure` signature.
- Consumes: shared claim/gap/brief indexes and Tasks 3–4 partial reviews.
- Produces `coverage-review.json` schema `3.0` for v2 and unchanged schema `2.0` for v1.

- [ ] **Step 1: Write evidence and visibility RED tests**

Cover every element status, wrong-source citations, neighboring citation spans, analysis claims, relationship evidence, consolidated prose, and detached relationships:

```python
def test_related_atoms_may_share_one_visible_item() -> None:
    draft = duty_exception_draft(shared_visible_item=True)
    review = evaluate_atomic_coverage(units(), leads(), draft, sources())
    assert review["valid"] is True


def test_visible_penalty_without_trigger_relationship_fails() -> None:
    draft = penalty_draft(relationship_visible=False)
    review = evaluate_atomic_coverage(units(), leads(), draft, sources())
    assert "ATOMIC_RELATIONSHIP_NOT_VISIBLE" in issue_codes(review)
```

Assert a source-supported claim must exactly support each `STATED` element and every relationship claim must bind evidence from both endpoint source contexts.

- [ ] **Step 2: Run focused tests and capture RED**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py -q -k 'evidence or visible or consolidated or detached'
```

- [ ] **Step 3: Validate exact evidence per stated element**

For each stated element, resolve its claim IDs through the shared claim index. Require source-supported kind, at least one exact citation, and overlap with at least one target assigned to the atom. Across the atom's stated elements, require every assigned unit and lead to receive exact evidence. `NOT_ESTABLISHED` elements require valid source-tied gaps.

- [ ] **Step 4: Validate visible atom bindings**

Critical and material atoms must occur in a `legal_analysis` paragraph, item, or row through `atom_ids`. Supporting atoms may remain internal only when no source-review dimension depends on them and no visible relationship requires them; otherwise they must be visible. A visible atom unit must include the claims for every stated element represented there.

- [ ] **Step 5: Validate visible relationship bindings**

Every material relationship appears in `relationship_ids` on one legal-analysis unit. That unit must also bind both endpoint atom IDs and at least one relationship claim. This permits one coherent sentence or table row while preventing detached consequences and exceptions.

- [ ] **Step 6: Compose and hash the v2 review**

```python
def compose_atomic_coverage_review(
    *,
    target_review: Mapping[str, object],
    rule_graph: Mapping[str, object],
    counts: Mapping[str, int],
    issues: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    payload = {
        "schema_version": "3.0",
        "coverage_contract_version": "proposition-coverage-v2",
        "valid": len(issues) == 0,
        "target_review": dict(target_review),
        "rule_graph": dict(rule_graph),
        "counts": dict(counts),
        "issues": [dict(issue) for issue in issues],
    }
    payload["coverage_review_hash"] = sha256_digest(canonical_json_bytes(payload))
    return payload
```

Canonicalize issue and count ordering before calling this composer. Dispatch v1 to its existing evaluator and v2 to `evaluate_atomic_coverage`, which calls this composer after Tasks 3–5 pass. Preserve the v1 lead-review projection. Add a v2 projection from lead dispositions into the unchanged legacy lead-recall check, with gap taking precedence over not-material.

- [ ] **Step 7: Run v1/v2 and deterministic-hash suites**

```bash
.venv/bin/pytest tests/analysis/test_atomic_coverage.py tests/analysis/test_proposition_coverage.py tests/analysis/test_coverage.py -q
```

- [ ] **Step 8: Commit Task 5**

```bash
git add src/regulatory_harvest/analysis/atomic_coverage.py src/regulatory_harvest/analysis/proposition_coverage.py src/regulatory_harvest/analysis/__init__.py tests/analysis/test_atomic_coverage.py tests/analysis/test_proposition_coverage.py
git commit -m "feat: enforce atomic evidence closure"
```

### Task 6: Prepare/finalize version dispatch and backward replay

**Files:**
- Modify: `scripts/harvest_skill.py`
- Modify: `src/regulatory_harvest/analysis/prompts/build-v1.md`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/e2e/test_skill_flow.py`
- Modify: `tests/scripts/test_evaluation_capsule_provenance.py`

**Interfaces:**
- Consumes: Task 5 version-dispatched closure.
- Produces: v2 dossiers by default, v2 review before report rendering, and unchanged explicit legacy handling.

- [ ] **Step 1: Write prepare/finalize RED tests**

Assert new prepare emits `proposition-coverage-v2`; a v2 dossier rejects missing, null, v1, or malformed draft contract with bounded review rather than raw `INVALID_DRAFT`; a completed v1 fixture retains exact receipt/report/bundle/replay bytes.

```python
def test_new_prepare_and_finalize_require_v2(tmp_path: Path) -> None:
    dossier = prepare(charter_path, tmp_path)
    assert dossier["coverage_contract_version"] == "proposition-coverage-v2"
    receipt, status = finalize(tmp_path, complete_v2_draft(tmp_path))
    assert status == 0
    assert receipt["proposition_coverage_valid"] is True
```

- [ ] **Step 2: Run runner and e2e tests and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py tests/scripts/test_evaluation_capsule_provenance.py -q -k 'v2 or legacy_replay'
```

- [ ] **Step 3: Default new dossiers to v2**

Export separate constants for v1 and v2. `prepare` writes v2. `finalize` selects from the dossier, not merely the draft. It writes `coverage-review.json` before report rendering on both success and review-required paths.

- [ ] **Step 4: Preserve explicit v1 finalization**

Legacy is selected only when the dossier explicitly identifies the v1 contract or both historical contract keys are absent under the existing legacy rule. Do not treat explicit null or mismatched contract values as legacy. Preserve current finalization-specific malformed-version diagnostic handling.

- [ ] **Step 5: Migrate the successful e2e fixture to v2**

Use a short fictional law with a duty and exception in one source unit. Author two atoms and an `exception_to` relationship, bind both to one Key Requirements bullet, and keep Implementation Workplan separate. Assert report prose remains natural and contains no atom IDs.

- [ ] **Step 6: Run full runner/e2e/provenance tests**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py tests/scripts/test_evaluation_capsule_provenance.py tests/analysis -q
```

- [ ] **Step 7: Commit Task 6**

```bash
git add scripts/harvest_skill.py src/regulatory_harvest/analysis/prompts/build-v1.md tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py tests/scripts/test_evaluation_capsule_provenance.py
git commit -m "feat: finalize new matters with atomic coverage"
```

### Task 7: Standalone portable v2 parity

**Files:**
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_harvest_portable.py`

**Interfaces:**
- Consumes: exact v2 contract and canonical output from Tasks 1–6.
- Produces: dependency-free parse, validation, coverage review, receipt, report, audit, and bundle parity.

- [ ] **Step 1: Add table-driven full/portable RED vectors**

Include valid duty+exception, deadline, enforcement+penalty, cross-reference, non-English, gap, not-material navigation, consolidated brief, every missing relationship, every malformed nested field, unhashable/list scalar, duplicate identifier, and contract mismatch.

For each vector assert:

```python
assert canonical_json_bytes(portable_review) == canonical_json_bytes(full_review)
assert raw_portable_input == before_portable
assert typed_full_input.model_dump(mode="json") == before_full
```

- [ ] **Step 2: Run the parity set and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_harvest_portable.py -q -k 'atomic or v2 or relationship_parity'
```

- [ ] **Step 3: Mirror strict v2 parsing**

Add standalone parsers for unit dimensions, lead dispositions, atom elements, atoms, relationships, and brief bindings. Accept v1 unchanged. Raw malformed inputs return the same bounded diagnostics or `INVALID_DRAFT` at the same boundary as full runtime.

- [ ] **Step 4: Mirror reconciliation and canonicalization**

Port target, rule-graph, exact-evidence, visibility, lead projection, issue sorting, count sorting, and hash logic without package imports. Use the same fixed vocabulary and messages.

- [ ] **Step 5: Mirror prepare/finalize selection**

New portable prepare emits v2. Portable finalize writes the same v2 review and receipt fields in the same order and preserves explicit v1 behavior.

- [ ] **Step 6: Run the complete portable and neighboring suite**

```bash
.venv/bin/pytest tests/scripts/test_harvest_portable.py tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py tests/analysis -q
.venv/bin/ruff check scripts/harvest_portable.py tests/scripts/test_harvest_portable.py
```

- [ ] **Step 7: Commit Task 7**

```bash
git add scripts/harvest_portable.py tests/scripts/test_harvest_portable.py
git commit -m "feat: mirror atomic coverage in portable runtime"
```

### Task 8: Skill contract, template, package, and adversarial gate

**Files:**
- Modify: `assets/analysis-draft.template.json`
- Modify: `SKILL.md`
- Modify: `references/draft-schema.md`
- Modify: `references/research-protocol.md`
- Modify: `scripts/skill-package-files.txt`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `docs/release-checklist.md`

**Interfaces:**
- Consumes: complete v2 runtime.
- Produces: one self-contained skill that internally authors source reviews and atom graphs but delivers only the normal attorney memo and verification artifacts.

- [ ] **Step 1: Write static/template RED tests**

Require the template to parse through full and portable models and include:

- all nine dimensions for every example unit review;
- one mapped duty lead and one explicit nonmaterial lead;
- distinct duty and exception atoms;
- one visible `exception_to` relationship;
- a source-tied timing gap; and
- a Key Requirements item binding related atoms without exposing IDs in rendered prose.

Require instructions to say that broad unit mapping is insufficient, independent actions become distinct atoms, genuine gaps remain gaps, and related atoms may share natural prose.

- [ ] **Step 2: Run template and skill tests and capture RED**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py -q -k 'atomic or v2_template or rule_relationship'
```

- [ ] **Step 3: Replace the fictional template with complete v2 data**

Use only `__REPLACE__` identifiers and fictional source content. Keep `lead_reviews` empty for v2. Ensure no field teaches benchmark-specific category choices.

- [ ] **Step 4: Update the internal authoring workflow**

Teach this order:

1. read every source;
2. complete every unit dimension and lead disposition;
3. build atomic rules and typed relationships;
4. challenge exceptions, thresholds, triggers, consequences, and cross-references;
5. bind exact claims;
6. write natural report prose with atom and relationship bindings;
7. finalize, repair every finite diagnostic, and deliver only after all three validation booleans are true.

Explicitly state that the attorney never edits the atom graph and that the graph is not rendered as a database view.

- [ ] **Step 5: Add new production files to the sorted package manifest**

Include `atomic_coverage.py` and `coverage_common.py`. Extend clean archive tests to require both modules and the updated template.

- [ ] **Step 6: Run focused, full, static, and package verification**

```bash
.venv/bin/pytest tests/analysis tests/scripts/test_harvest_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_build_skill.py tests/e2e/test_skill_flow.py -q
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
git diff --check
```

- [ ] **Step 7: Perform the adversarial review**

Probe at least:

- a unit with two independent duties incorrectly mapped to one list-valued action;
- an exception categorized as context or not-present;
- a deadline citation adjacent to but outside its target;
- a penalty visible without the triggering violation;
- a relationship bound to only one endpoint;
- a cross-source atom with evidence from only one source;
- duplicate/cyclic/unknown relationship IDs;
- validation-bypassing typed and raw malformed fields;
- v1 replay drift; and
- full/portable input mutation or byte divergence.

Fix every Critical or Important finding through a new failing test before production code.

- [ ] **Step 8: Build twice and smoke the clean archive**

Build twice from the same committed snapshot, require byte-identical archives, extract one, and run both full and `python3 -I -S` portable `prepare --help` and `finalize --help`. Run the release privacy audit without publishing.

- [ ] **Step 9: Commit Task 8**

```bash
git add assets/analysis-draft.template.json SKILL.md references/draft-schema.md references/research-protocol.md scripts/skill-package-files.txt tests/scripts/test_build_skill.py tests/scripts/test_harvest_skill.py docs/release-checklist.md
git commit -m "docs: require atomic legal coverage"
```

- [ ] **Step 10: Record the v2 completion gate**

Record commit range, RED/GREEN evidence, test counts, static results, archive hash, independent review findings, and any deferred Minor item in the execution progress artifact. Do not run the private substantive gate until the evaluator-reliability plan is also complete and reviewed.
