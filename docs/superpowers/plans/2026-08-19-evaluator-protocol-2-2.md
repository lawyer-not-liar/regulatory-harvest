# Evaluator Protocol 2.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a strict Protocol 2.2 evaluator whose internal semantic drafts compile deterministically, whose source review and audit are bounded fragments, and whose internal mechanical failures leave an exact pending run that can resume instead of ending the evaluation.

**Architecture:** Add a separate Protocol 2.2 model, draft-compiler, request, semantic-compiler, artifact, and workflow surface beside replay-only Protocols 1.3, 2.0, and 2.1. Internal roles return bounded semantic drafts; deterministic code normalizes only provable mechanical equivalents, builds the strict response envelope, and uses the ordinary preflight and atomic commit boundary. Failed internal compilation leaves the current request and accepted history unchanged, while public strict submissions remain fail-closed and write-free.

**Tech Stack:** Python 3.11+, Pydantic 2.8+, pytest 8.3+, pytest-asyncio 0.24+, standard-library portable mirror, Ruff, mypy, canonical UTF-8 JSON, SHA-256 artifact and compiler-contract binding.

**Spec:** `docs/superpowers/specs/2026-08-19-evaluator-protocol-2-2-design.md`

## Global Constraints

- Protocol 2.2 is explicit and experimental during implementation. Protocol 2.1 remains the new-run default until every public gate, one separately authorized private gate, and a separate owner default decision pass.
- Protocols 1.3, 2.0, and 2.1 remain byte-exact replay/read-only. Never relabel, rewrite, migrate, or resume them as Protocol 2.2.
- Internally generated drafts are not persisted evaluator responses. Only controller-compiled strict responses may reach preflight and commit.
- Deterministic code owns protocol metadata, operation, case and request fingerprints, provider and model provenance, isolation metadata, identifiers, ordering, artifact paths, canonical bytes, aggregate fingerprints, and manifest transitions.
- Source-review and source-audit fragments contain at most five new items. Each operation permits at most 128 fragments and 640 compiled items.
- Only mechanically provable equivalents may normalize. Missing or ambiguous substance must return a bounded clarification reason rather than a guessed value.
- Low-quality but mechanically interpretable, request-bound, evidence-grounded semantic judgments are accepted and evaluated downstream. Mechanical validation is not a hidden merits filter.
- One driver invocation permits one initial draft and at most one fresh clarification for the same fragment. Rejected draft bytes are never persisted, summarized, or supplied to the clarification role.
- Exhausted internal recovery returns `EVALUATION_ENGINE_PAUSED`, process exit `6`, and an exact unchanged nonterminal run with one pending request.
- New Protocol 2.2 runs never create `INCONCLUSIVE_MECHANICAL`. Only `COMPLETED` and approved substantive `INCONCLUSIVE` are terminal.
- External invalid strict submissions remain write-free and pending. They do not terminalize the run.
- Resume verifies the whole run, reuses the exact pending request, never repeats an accepted fragment, and requires the exact compiler-contract fingerprint.
- Strict source/report evidence, case, report, grader, lane, dispute, batch, path, symlink, hash, inventory, atomic-write, rollback-ownership, semantic-replay, privacy, and full/portable parity checks remain mandatory.
- Shared storage uses contract `cooperative-exclusive-directory-namespace-per-operation-v1`: all evaluator components coordinate exclusive evaluator-owned directory names during each evaluator storage operation. It does not defend against arbitrary same-UID directory rename or replacement between syscalls; observed identity/root/symlink changes, no-clobber collisions, tampered bytes, crashes, rollback, and recovery remain in scope.
- No private evaluation, publication action, maturity claim, benchmark claim, or default-protocol change is authorized by Tasks 1 through 9.

## File Structure

New focused full-runtime modules:

- `src/regulatory_harvest/evaluation/attorney_v22_models.py`: strict persisted Protocol 2.2 types, fragments, aggregates, manifest, state, and results.
- `src/regulatory_harvest/evaluation/attorney_v22_drafts.py`: tolerant bounded draft types, safe normalization, evidence resolution, compiler outcomes, and strict response construction.
- `src/regulatory_harvest/evaluation/attorney_v22_requests.py`: compiler-contract descriptor and fingerprint plus source-review, source-audit, referee, ordinary-grade, and contested-grade request builders.
- `src/regulatory_harvest/evaluation/attorney_v22_compiler.py`: review/audit aggregation, dispute construction, baseline compilation, grade aggregation, and v2.2 fingerprinting.
- `src/regulatory_harvest/evaluation/attorney_v22_artifacts.py`: Protocol 2.2 initialization, atomic transitions, exact replay, pending-run verification, and loaders.
- `src/regulatory_harvest/evaluation/attorney_v22_workflow.py`: strict submission API, draft driver, pause outcome, resume API, and substantive completion.

New focused tests mirror those modules under `tests/evaluation/`.

Existing integration files:

- `src/regulatory_harvest/evaluation/__init__.py`
- `src/regulatory_harvest/evaluation/attorney_protocol.py`
- `src/regulatory_harvest/cli.py`
- `src/regulatory_harvest/evaluation/attorney_cli.py`
- `scripts/attorney_eval_full.py`
- `scripts/harvest_skill.py`
- `scripts/attorney_eval_portable.py`
- `scripts/harvest_portable.py`
- `scripts/skill-package-files.txt`
- `scripts/build_skill.py`
- `README.md`
- `SKILL.md`
- `docs/evaluation.md`
- `references/attorney-evaluation.md`
- `assets/attorney-evaluation-v22-response.template.json`
- CLI, package, portable, and skill tests named below

The portable mirror remains in `scripts/attorney_eval_portable.py` because it must run under `python3 -I -S`. It must derive behavior from the same canonical compiler-contract descriptor and exact differential vectors, not import installed package modules.

---

### Task 1: Strict Protocol 2.2 Models and Compiler Contract

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v22_models.py`
- Create: `tests/evaluation/test_attorney_v22_models.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: strict JSON helpers, semantic enums, evidence types, rubric concepts, and report dispositions from `attorney_v2_models.py` and `attorney_v21_models.py` without reusing their serialized protocol wrappers.
- Produces: `PROTOCOL_V22`, `EvaluatorOperationV22`, `EvaluationPhaseV22`, `EvaluationTerminalStatusV22`, `IndexedProposalV22`, `IndexedAuditConcernV22`, `SourceReviewFragmentV22`, `AcceptedSourceReviewFragmentV22`, `SourceAuditFragmentV22`, `AcceptedSourceAuditFragmentV22`, `SourceReviewAggregateV22`, `SourceAuditAggregateV22`, `EvaluatorRequestV22`, `EvaluatorResponseV22`, `EvaluationCallRecordV22`, `EvaluationManifestV22`, `EvaluationRunStateV22`, `EvaluationResultV22`, and strict v2.2 referee, baseline, grade, reconciliation, and sensitivity types.

- [ ] **Step 1: Write strict model RED tests**

Add tests for the exact operation enum, five-item source fragments, final/nonfinal progress, terminal grammar without mechanical terminal, one pending call, compiler-contract binding, immutable nested payloads, and rejection of any serialized `2.1` wrapper.

```python
def test_v22_operation_enum_is_exact() -> None:
    assert {item.value for item in EvaluatorOperationV22} == {
        "source_review_fragment",
        "source_audit_fragment",
        "source_referee_fragment",
        "ordinary_grade_fragment",
        "contested_grade_fragment",
    }


def test_v22_has_no_mechanical_terminal() -> None:
    assert {item.value for item in EvaluationTerminalStatusV22} == {
        "COMPLETED",
        "INCONCLUSIVE",
    }
```

- [ ] **Step 2: Run the focused model RED**

Run:

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_models.py -q
```

Expected: collection fails because `attorney_v22_models` does not exist.

- [ ] **Step 3: Implement the strict protocol surface**

Use exact literals and closed immutable models. The defining shapes include:

```python
PROTOCOL_V22: Literal["2.2"] = "2.2"


class EvaluatorOperationV22(StrEnum):
    SOURCE_REVIEW_FRAGMENT = "source_review_fragment"
    SOURCE_AUDIT_FRAGMENT = "source_audit_fragment"
    SOURCE_REFEREE_FRAGMENT = "source_referee_fragment"
    ORDINARY_GRADE_FRAGMENT = "ordinary_grade_fragment"
    CONTESTED_GRADE_FRAGMENT = "contested_grade_fragment"


class EvaluationTerminalStatusV22(StrEnum):
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SourceReviewFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    proposals: tuple[SemanticProposal, ...] = Field(max_length=5)
    review_complete: bool


class SourceAuditFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    concerns: tuple[AuditConcernV22, ...] = Field(max_length=5)
    audit_complete: bool


class AcceptedSourceReviewFragmentV22(V22StrictModel):
    fragment_ordinal: int = Field(ge=1, le=128)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: SourceReviewFragmentV22


class AcceptedSourceAuditFragmentV22(V22StrictModel):
    fragment_ordinal: int = Field(ge=1, le=128)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: SourceAuditFragmentV22


class SourceReviewAggregateV22(V22StrictModel):
    proposals: tuple[IndexedProposalV22, ...] = Field(max_length=640)
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=128)
    aggregate_fingerprint: Hash


class SourceAuditAggregateV22(V22StrictModel):
    concerns: tuple[IndexedAuditConcernV22, ...] = Field(max_length=640)
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=128)
    aggregate_fingerprint: Hash
```

Require nonfinal source fragments to contain at least one new item. Define manifest fields for `compiler_contract_fingerprint`, source-review aggregate fingerprint, source-audit aggregate fingerprint, existing referee/baseline/grade/sensitivity/result fingerprints, ordered calls, artifact inventory, and exactly zero or one pending call.

- [ ] **Step 4: Export and verify the models**

Run:

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_models.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v22_models.py tests/evaluation/test_attorney_v22_models.py src/regulatory_harvest/evaluation/__init__.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v22_models.py
```

Expected: all pass.

- [ ] **Step 5: Commit the model boundary**

```bash
git add src/regulatory_harvest/evaluation/attorney_v22_models.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_v22_models.py
git commit -m "feat: define evaluator protocol 2.2 models"
```

---

### Task 2: Bounded Draft Compiler and Safe Normalization

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v22_drafts.py`
- Create: `tests/evaluation/test_attorney_v22_drafts.py`

**Interfaces:**
- Consumes: `EvaluatorRequestV22`, `EvaluatorResponseV22`, operation-specific strict payloads, and request-contained frozen evidence from Task 1.
- Produces: `EvaluatorProvenanceV22`, `EvaluatorDraftPromptV22`, `DraftReasonCodeV22`, `CompiledDraftV22`, `NeedsClarificationV22`, `EngineDefectV22`, `DraftCompileOutcomeV22`, `parse_evaluator_draft_v22()`, and `compile_evaluator_draft_v22()`.

- [ ] **Step 1: Write compiler RED tests before implementation**

Cover all five operations and these exact categories: key-order/whitespace normalization, case-folded approved enum alias, exact evidence, unique whitespace-only evidence resolution, ambiguous evidence, missing substance, unknown reference, exact duplicate removal, nonidentical conflict, five-item limit, cyclic input, oversized input, and no case/punctuation/Unicode-content quote mutation.

```python
def test_unique_whitespace_quote_compiles_to_exact_source_bytes(request) -> None:
    draft = valid_review_draft(quote="The  controller  shall act.")
    outcome = compile_evaluator_draft_v22(request, draft, provenance())
    assert isinstance(outcome, CompiledDraftV22)
    passage = outcome.response.payload["proposals"][0]["passages"][0]
    assert passage["quote"] == "The controller shall act."


def test_ambiguous_normalized_quote_needs_clarification_without_guessing(request) -> None:
    outcome = compile_evaluator_draft_v22(request, ambiguous_quote_draft(), provenance())
    assert outcome == NeedsClarificationV22((DraftReasonCodeV22.EVIDENCE_AMBIGUOUS,))
```

- [ ] **Step 2: Run the compiler RED**

Run:

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_drafts.py -q
```

Expected: collection fails because `attorney_v22_drafts` does not exist.

- [ ] **Step 3: Implement draft and outcome types**

Define bounded extra-forbid draft models with evaluator-authored strings and local ordinals only. Use a discriminated result union:

```python
@dataclass(frozen=True)
class CompiledDraftV22:
    response: EvaluatorResponseV22
    normalization_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class NeedsClarificationV22:
    reason_codes: tuple[DraftReasonCodeV22, ...]


@dataclass(frozen=True)
class EngineDefectV22:
    reason_code: Literal["COMPILER_INVARIANT", "COMPILER_PREFLIGHT_DISAGREEMENT"]


DraftCompileOutcomeV22 = CompiledDraftV22 | NeedsClarificationV22 | EngineDefectV22
```

`EvaluatorDraftPromptV22` contains the exact request, attempt `1 | 2`, and safe clarification codes. It never contains rejected draft bytes.

- [ ] **Step 4: Implement deterministic compilation**

Use one public function:

```python
def compile_evaluator_draft_v22(
    request: EvaluatorRequestV22,
    draft: object,
    provenance: EvaluatorProvenanceV22,
) -> DraftCompileOutcomeV22:
    try:
        parsed = _parse_operation_draft_v22(request.operation, draft)
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        return NeedsClarificationV22(_draft_validation_reason_codes_v22(error))
    try:
        payload, normalization_codes = _compile_operation_payload_v22(request, parsed)
    except _DraftNeedsClarificationV22 as error:
        return NeedsClarificationV22(tuple(sorted(set(error.reason_codes))))
    try:
        response = EvaluatorResponseV22(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name=provenance.provider_name,
            model_name=provenance.model_name,
            judge_isolation=provenance.judge_isolation,
            payload=payload,
        )
    except (TypeError, ValidationError, ValueError, RecursionError):
        return EngineDefectV22("COMPILER_INVARIANT")
    return CompiledDraftV22(response, tuple(sorted(set(normalization_codes))))
```

Define `_DraftNeedsClarificationV22`, `_draft_validation_reason_codes_v22()`, `_parse_operation_draft_v22()`, and `_compile_operation_payload_v22()` in the same module. Input-caused parse validation always becomes `NeedsClarification`; only failure to construct the strict response from already compiled payload data becomes `EngineDefect`. The public function must parse bounded JSON, select the operation-specific draft model, normalize only the spec allowlist, resolve evidence solely from the request payload, construct controller-owned envelope fields, validate `EvaluatorResponseV22`, and return safe sorted unique reason codes for noncompilable drafts.

- [ ] **Step 5: Prove content quality is not a mechanical gate**

Add a grounded but deliberately weak semantic proposal and assert compilation succeeds. Add an ungrounded quote and assert clarification rather than a merits label.

```python
def test_grounded_but_unpersuasive_judgment_still_compiles(request) -> None:
    outcome = compile_evaluator_draft_v22(request, weak_but_bound_draft(), provenance())
    assert isinstance(outcome, CompiledDraftV22)
```

- [ ] **Step 6: Run focused tests and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_drafts.py tests/evaluation/test_attorney_v22_models.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v22_drafts.py tests/evaluation/test_attorney_v22_drafts.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v22_drafts.py
```

Expected: all pass.

- [ ] **Step 7: Commit the compiler**

```bash
git add src/regulatory_harvest/evaluation/attorney_v22_drafts.py tests/evaluation/test_attorney_v22_drafts.py
git commit -m "feat: compile evaluator semantic drafts"
```

---

### Task 3: Fragment Requests, Aggregates, and Compiler Fingerprint

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v22_requests.py`
- Create: `src/regulatory_harvest/evaluation/attorney_v22_compiler.py`
- Create: `tests/evaluation/test_attorney_v22_requests.py`
- Create: `tests/evaluation/test_attorney_v22_compiler.py`

**Interfaces:**
- Consumes: Task 1 strict types, Task 2 draft payload contracts, frozen case envelopes, and Protocol 2.1 substantive referee/grading rules.
- Produces: `COMPILER_CONTRACT_V22`, `COMPILER_CONTRACT_FINGERPRINT_V22`, exact request builders, `aggregate_source_review_fragments_v22()`, `aggregate_source_audit_fragments_v22()`, v2.2 dispute/baseline functions, and v2.2 grade/reconciliation/sensitivity functions.

- [ ] **Step 1: Write request and aggregate RED tests**

Require exact request fingerprints, complete source-only evidence, accepted inventory carry-forward, fragment ordinals, five-item maximums, deterministic call ordering, review/audit finalization, 128-fragment and 640-item ceilings, and rejection of duplicate/skipped fragments.

```python
def test_second_review_request_carries_only_compiled_accepted_inventory(envelope) -> None:
    first = accepted_review_fragment("A controller shall act.")
    request = build_source_review_fragment_request_v22(envelope, (first,), fragment_ordinal=2)
    assert request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
    assert request.payload["accepted_proposals"] == [first.proposals[0].model_dump(mode="json")]
    assert request.payload["max_new_proposals"] == 5
```

- [ ] **Step 2: Run the request/compiler RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py -q
```

Expected: collection fails because both modules are absent.

- [ ] **Step 3: Define and hash the complete compiler contract**

Create one canonical JSON descriptor containing protocol `2.2`, every operation, draft and strict schema hash, enum alias table, evidence-normalization version, fragment maximum `5`, per-operation fragment maximum `128`, item maximum `640`, ordering version, compiler version, aggregate version, and rubric version.

```python
COMPILER_CONTRACT_FINGERPRINT_V22 = sha256_digest(
    canonical_json_bytes(COMPILER_CONTRACT_V22)
)
```

Every request safe-metadata block and every manifest must bind this fingerprint.

- [ ] **Step 4: Implement source-review and source-audit request sequences**

Provide these exact builders:

```python
def build_source_review_fragment_request_v22(
    envelope: CaseEnvelope,
    accepted: tuple[AcceptedSourceReviewFragmentV22, ...],
    *,
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    record, record_fingerprint = _frozen_source_record_v22(envelope)
    proposals = [
        proposal.model_dump(mode="json")
        for fragment in accepted
        for proposal in fragment.payload.proposals
    ]
    return _new_request_v22(
        EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
        json_schema=SourceReviewFragmentV22.model_json_schema(),
        payload={
            "source_record": record,
            "accepted_proposals": proposals,
            "fragment_ordinal": fragment_ordinal,
            "max_new_proposals": 5,
        },
        safe_metadata={"source_record_fingerprint": record_fingerprint},
    )


def build_source_audit_fragment_request_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    accepted: tuple[AcceptedSourceAuditFragmentV22, ...],
    *,
    fragment_ordinal: int,
) -> EvaluatorRequestV22:
    record, record_fingerprint = _frozen_source_record_v22(envelope)
    return _new_request_v22(
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
        json_schema=SourceAuditFragmentV22.model_json_schema(),
        payload={
            "source_record": record,
            "indexed_proposals": review.model_dump(mode="json")["proposals"],
            "accepted_concerns": [
                concern.model_dump(mode="json")
                for fragment in accepted
                for concern in fragment.payload.concerns
            ],
            "fragment_ordinal": fragment_ordinal,
            "max_new_concerns": 5,
        },
        safe_metadata={"source_record_fingerprint": record_fingerprint},
    )
```

Define `_frozen_source_record_v22()` and `_new_request_v22()` in the same module. Rebuild referee and grade request helpers under Protocol 2.2 so no serialized `2.1` schema leaks into a new run.

- [ ] **Step 5: Implement deterministic aggregation and downstream semantics**

Review and audit aggregation must preserve fragment order, prove no duplicate semantic item, assign controller references, and fingerprint the exact fragment list. Reuse Protocol 2.1 substantive algorithms only through value conversion with explicit v2.2 output reconstruction; never persist a Protocol 2.1 wrapper.

- [ ] **Step 6: Run focused and neighboring semantic tests**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py tests/evaluation/test_attorney_v21_compiler.py tests/evaluation/test_attorney_v21_rubric.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v22_requests.py src/regulatory_harvest/evaluation/attorney_v22_compiler.py tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v22_requests.py src/regulatory_harvest/evaluation/attorney_v22_compiler.py
```

Expected: all pass.

- [ ] **Step 7: Commit request and aggregation semantics**

```bash
git add src/regulatory_harvest/evaluation/attorney_v22_requests.py src/regulatory_harvest/evaluation/attorney_v22_compiler.py tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py
git commit -m "feat: fragment evaluator source analysis"
```

- [ ] **Authorized remediation: replace serialization-first validation with one raw-wire boundary**

The owner authorized a general Task 3 refactor after the bounded repair loop
proved that `model_dump()` can coerce invalid `model_construct()` values before
strict validation sees them. Define one cycle-safe raw-wire snapshot and strict
rehydration path for every controller-owned Protocol 2.2 value entering the
request/compiler surface. No public request, aggregation, baseline, grade,
reconciliation, or sensitivity boundary may serialize a Pydantic model before
the first strict/contextual validation pass.

The remediation must:

- route source-review and source-audit histories, referee disputes/fragments,
  canonical baselines, ordinary and contested grade fragments, grader
  aggregates, reconciliations, rubrics, and contested request inputs through
  the same raw-wire invariant;
- preserve contextual inventory validation and recompute controller hashes only
  after strict rehydration;
- reject nested boolean/string/float coercions, invalid enums, cycles, and
  `model_construct()` bypasses without logging rejected values;
- retain valid low-quality evaluator content and all recoverable Task 2 draft
  outcomes;
- add a parameterized boundary matrix plus the finite source-architecture
  policy below; and
- receive a fresh independent review before Task 4 begins.

#### Owner-authorized final Task 3 source-policy boundary: syntax gate and review inventories

The owner authorized this replacement after the canonical-call implementation
stopped at `7b9f5199f14b489dc16dde5b25c6420a9ebd47f3`. The remaining Important
findings were in the bespoke static analyzer, not the runtime raw-wire boundary:
it modeled Python class scope and definition/import execution order incorrectly,
and provider roots remained mutable through root deletion or
`__setattr__`/`__delattr__`.

Abandon the custom Python name-resolution, rebinding, callable-origin,
module-root-origin, and provider-provenance theorem. Do not claim to resolve
Python lexical semantics. Replace it with:

1. the universal canonical `Call.func` shape rule;
2. the finite syntax-only bans below; and
3. exact inspectable inventories that force human review when governed source
   changes.

Runtime raw-wire rehydration, contextual validation, replay, resource bounds,
adversarial/equivalence tests, Ruff, and mypy remain authoritative. The static
check is development-only: it cannot emit an evaluator response, consume a
draft or substantive repair attempt, change a pending request, pause/resume a
run, or create `PASS`, `FAIL`, `INCONCLUSIVE`, or a mechanical terminal.
A failure blocks progression to Task 4; it never ends or changes an evaluation.

##### Inventoried starting point

At exact HEAD `7b9f5199`, Python 3.13.6 finds:

| Source | Calls | Targets | Imports | Definitions | Simple subscript assignments |
| --- | ---: | --- | ---: | ---: | ---: |
| `attorney_v22_requests.py` | 181 | 141 `Name`, 40 `Attribute` | 43 | 21 | 1 |
| `attorney_v22_compiler.py` | 310 | 241 `Name`, 69 `Attribute` | 50 | 36 | 9 |
| **Total** | **491** | **382 `Name`, 109 `Attribute`** | **93** | **57** | **10** |

Both files have zero `Delete`, zero `Attribute` Store/Del, zero non-simple
`Subscript` Store/Del, zero indirect `AugAssign`/`AnnAssign` targets,
zero forbidden reflective lexemes, and zero wildcard imports.

The ten subscript writes are direct single-target `Assign` statements used for
local dictionaries: requests has `raw["request_fingerprint"]`; compiler has
two `seen[identity]` writes and seven local raw/legacy field writes. Freeze
them as review evidence. This syntactic allowance is not a claim about arbitrary
subscript mutation.

##### Blocking finite syntax rules

Keep the existing total call classifier. Only a direct `Name` or a
one-to-three-hop `Attribute` chain rooted in a `Name` is allowed. Every
`ast.Call`, including inner calls under an invalid outer call, is visited.
Non-Attribute failures remain `dynamic-call-target:<kind>`; non-Name
Attribute roots remain `attribute-call-target-root:<kind>`; a fourth
Name-rooted hop remains `call-target-depth`. The classifier makes no claim
about what the spelling resolves to.

Add one separate total syntax traversal:

- any `ast.Delete` -> `delete-statement`; do not also diagnose its targets;
- `AugAssign` targeting `Attribute`/`Subscript` ->
  `indirect-augmented-assignment`;
- `AnnAssign` targeting `Attribute`/`Subscript` ->
  `indirect-annotated-assignment`;
- other `Attribute` Store contexts -> `attribute-store`;
- `Subscript` Store is allowed only as the sole direct target of ordinary
  `Assign`; every other form -> `non-simple-subscript-store`;
- wildcard import -> `wildcard-import`;
- importing `builtins`, `operator`, or `importlib`, or one of their denied
  provider symbols -> `reflective-import`; and
- any `Name` or `Attribute.attr` reference using a denied lexeme ->
  `reflective-lexeme`, whether or not called.

```python
_FORBIDDEN_REFLECTIVE_NAMES = frozenset(
    {
        "getattr", "setattr", "delattr", "globals", "locals", "vars",
        "eval", "exec", "compile", "__import__", "__builtins__", "__dict__",
        "__getattribute__", "__getattr__", "__setattr__", "__delattr__",
        "attrgetter", "itemgetter", "methodcaller", "import_module",
    }
)
_FORBIDDEN_REFLECTIVE_MODULES = frozenset({"builtins", "operator", "importlib"})
```

These bans intentionally reject harmless uses of those spellings. Current
governed source needs no exception. Do not add alias propagation, origin
resolution, scope/execution-order simulation, descriptor analysis, or
interprocedural callable flow.

Diagnostics are exact Counters of
`(source_basename, qualified_syntactic_owner_and_occurrence, display,
reason_code, structural_context_sha256)`. The owner locates syntax only; it is
not an effective Python scope. Structural call findings are one-per-call,
mutation findings follow the precedence above, and reflective findings are
additive.

##### Review-only exact inventories

Retain exact inspectable Counters for all 491 canonical calls; all 93 original
imports; all 57 definitions; direct validation/serialization policy calls and
the existing validation, serialization/output/V2.1-conversion, and neutral
zones; and the ten permitted simple subscript assignments.

A new, removed, moved, or recategorized row fails and must be listed as an
old/new Counter delta in the task report. Updating expected inventory requires
explicit human review of that delta and fresh independent review. Inventories
are drift/review tripwires, not proof against a malicious change that rewrites
both source and expected literals.

Remove the 662-row effective-binding census and blocking allowed-origin,
module-root-origin, and provider-path tables. Import provenance remains
inspectable evidence but no longer authorizes a call. Exact call inventories
document reviewed architecture; blocking correctness claims are limited to
call shape, finite syntax bans, policy-zone separation, runtime behavior,
Ruff, and mypy.

##### Parser-version matrix

The full suite already runs on Python 3.11, 3.12, 3.13, and 3.14. Every row must
parse the governed modules with zero findings and exercise the complete
parser-reachable `Call.func` corpus. Python 3.12+ type-alias/type-parameter
syntax is an ordinary allowed control, not a binding theorem. Python 3.14+
retains `TemplateStr` and constructed `Interpolation` rejection.

Require exact reasons/displays/multiplicity per mutation. Digests need be
deterministic within a parser version; do not claim cross-version AST-byte
identity. Normalize version-only empty AST fields before freezing inventories
so the governed inventories remain stable across 3.11-3.14.

- [ ] **Final-policy Step 1: Write RED syntax tests**

Add exact REDs for: deleting a Name/Attribute/Subscript; Attribute assignment,
for-target, and with-target; Attribute/Subscript augmented and annotated
assignment; Subscript for-target; wildcard import; `setattr`,
`value.__setattr__`, `value.__delattr__`; `import importlib`; and
`from operator import attrgetter as pick`.

Add safe controls for sole-target `mapping[key] = value`, ordinary Attribute
loads, normal imports, and unrelated method names. Assert all ten current
simple-subscript rows exactly.

- [ ] **Final-policy Step 2: Run RED on `7b9f5199`**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_compiler.py -q -k 'canonical_call_target or syntax_policy or source_inventory'
```

The general delete/write/dunder/non-simple-subscript/inventory rows must fail
before replacement. Record exact counts in the ignored Task 3 report.

- [ ] **Final-policy Step 3: Remove, do not repair, the theorem**

Delete effective-scope resolution, binding visitor/census, direct-callee origin
authorization, class/definition/import visibility logic, allowed-origin table,
module-root-origin proof, and provider-path proof. Implement only canonical
targets, finite syntax bans, review inventories, and existing policy-zone
checks. Keep it test-only in
`tests/evaluation/test_attorney_v22_compiler.py`.

- [ ] **Final-policy Step 4: Apply the exact test disposition**

Retain as blocking syntax tests:

- canonical target total/bounded, parser-corpus, constructed/versioned AST,
  TemplateStr, and positive-context tests;
- rewritten bounded reflective-denylist coverage; and
- the new delete/write/subscript/import syntax matrix.

Retain unchanged as runtime/equivalence authority:

- every Task 3 test before the source-policy section, including constructed
  scalar/enum/ordinal/lane/offset, hostile-container, aggregate seal,
  cross-case, grounding, bounded replay, referee, and strict-rubric matrices;
- `test_task3_split_leaves_preserve_public_fingerprint_and_baseline_results`;
- `test_task3_eight_production_call_splits_are_differentially_equivalent`.

Demote to review-only drift assertions: exact production calls, original
imports and safe ordinary aliases, definitions/zones, and the permitted
simple-subscript Counter.

Remove: effective-binding census; direct-origin/lexical-visibility;
lambda-default/body effective-scope; binding-form/global/nonlocal/comprehension/
match/annotation-scope; type-parameter binding registry; moved/shadowed import
authorization; module-root resolution; provider-path mutation tests; and their
binding/origin/root/provider expected literals.

- [ ] **Final-policy Step 5: Prove the boundary**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_compiler.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_models.py tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_models.py tests/evaluation/test_attorney_v22_drafts.py tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py tests/evaluation/test_attorney_v21_compiler.py tests/evaluation/test_attorney_v21_rubric.py -q
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py -q
PYTHONPATH=src ../../.venv/bin/ruff check .
PYTHONPATH=src ../../.venv/bin/mypy src
PYTHONPATH=src ../../.venv/bin/pytest -q
git diff --check
```

The full Python 3.11-3.14 CI matrix is required before public-gate readiness.
Local completion must state the exact runtime tested and may not infer unrun rows.

- [ ] **Final-policy Step 6: Fresh review, maximum two rounds**

This replacement receives at most two fresh implementation review rounds. Each
Critical/Important finding inside the stated syntax rules or retained runtime
boundary must reproduce RED and be fixed without reintroducing name resolution,
callable provenance, or general Python flow analysis.

Reviewers receive the exact diff, old/new inventory deltas, runtime adversarial
results, Ruff/mypy, full suite, and parser-version evidence. They verify total
call traversal; exact syntax precedence; zero governed-source findings; ten
explicit subscript writes; review-only inventory labeling; actual removal of
the theorem; unchanged runtime/equivalence coverage; and that no static finding
can enter evaluator state or terminate, pause, or resume an evaluation.

Concrete misses within these finite rules or runtime defects are in scope.
Demanding arbitrary Python name resolution, descriptors, or callable provenance
requires a new owner decision, not another scanner patch.

Task 4 remains blocked until the exact final Task 3 commit passes required
gates, accurately states parser-matrix evidence, has zero open
Critical/Important findings within this boundary, and receives independent
`Ready`.

---

### Task 4: Protocol Detection, Storage, and Exact Replay

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v22_artifacts.py`
- Create: `tests/evaluation/test_attorney_v22_artifacts.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_protocol.py`
- Modify: `tests/evaluation/test_attorney_protocol.py`

**Interfaces:**
- Consumes: Task 1 manifest/artifact models, Task 3 request and aggregation reconstruction, and shared no-follow storage primitives from `attorney_artifacts.py`.
- Produces: `initialize_v22_run_storage()`, `commit_v22_transition()`, `preflight_v22_response()`, `verify_v22_run()`, `load_verified_v22_run()`, and `load_verified_v22_context()`.

- [ ] **Step 1: Write detector and replay RED tests**

Cover protocol `2.2`, unknown/mixed/downgraded manifests, initialization inventory, partial review, partial audit, partial referee, partial grade, completed results, substantive inconclusive, pending-run verification, and absence of a mechanical terminal grammar.

```python
def test_pending_v22_run_is_valid_and_resumable(run_after_two_bad_drafts: Path) -> None:
    verification = verify_v22_run(run_after_two_bad_drafts)
    manifest, result = load_verified_v22_run(run_after_two_bad_drafts)
    assert verification.ok is True
    assert result is None
    assert manifest.terminal_status is None
    assert [call.state for call in manifest.calls].count("pending") == 1
```

- [ ] **Step 2: Run detector/replay RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_protocol.py tests/evaluation/test_attorney_v22_artifacts.py -q
```

Expected: Protocol 2.2 is unsupported and artifact module collection fails.

- [ ] **Step 3: Add canonical detection and immutable storage**

Add `2.2` to the exact detector allowlist without changing 1.3, 2.0, or 2.1 classification. Initialization writes case envelope, build/contract descriptor, rubric, first review-fragment request, and manifest through the existing ownership-aware atomic primitive.

The shared storage API and every evaluator component follow
`cooperative-exclusive-directory-namespace-per-operation-v1`: evaluator-owned
directory names are cooperatively exclusive for each complete storage operation.
Retain finite pre/post identity and post-`fchmod` checks as defense in depth, but
do not claim protection against an arbitrary same-UID renamer between every
syscall. A swap after the last successful check is outside the contract unless a
later check actually observes it.

- [ ] **Step 4: Implement full semantic replay**

Reconstruct every expected request, call, accepted fragment, source aggregate, dispute, referee aggregate, baseline, batch, grade fragment, lane aggregate, reconciliation, sensitivity, result, artifact inventory, and successor manifest from frozen inputs and accepted response bytes. Stored derived artifacts are comparison targets, never authority.

- [ ] **Step 5: Prove transaction and tamper boundaries**

Add before-replace, post-replace, post-verification, same-byte competitor, inode swap, source-fragment swap, skipped fragment, compiler-contract swap, resealed aggregate, resealed result, symlink, oversized, cyclic, and path-race tests. Reuse the shared storage primitive rather than adding another implementation.

Race tests must preserve realistic collisions, `EEXIST`, pre-operation and
post-operation identity failures, symlink/root swaps, crashes, recovery, and
no-clobber behavior. A test whose sole premise is arbitrary concurrent
same-authority replacement of evaluator directory names during one storage
operation is outside the contract. Keep a regression binding this scope so later
review cannot silently expand the threat model.

- [ ] **Step 6: Run full artifact/static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_artifacts.py tests/evaluation/test_attorney_v2_artifacts.py tests/evaluation/test_attorney_v21_artifacts.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_protocol.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v22_artifacts.py src/regulatory_harvest/evaluation/attorney_protocol.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_protocol.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v22_artifacts.py src/regulatory_harvest/evaluation/attorney_protocol.py
```

Expected: all pass.

- [ ] **Step 7: Commit storage and replay**

```bash
git add src/regulatory_harvest/evaluation/attorney_v22_artifacts.py src/regulatory_harvest/evaluation/attorney_protocol.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_protocol.py
git commit -m "feat: verify recoverable evaluator runs"
```

---

### Task 5: Recoverable Workflow and Resume API

**Files:**
- Create: `src/regulatory_harvest/evaluation/attorney_v22_workflow.py`
- Create: `tests/evaluation/test_attorney_v22_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`

**Interfaces:**
- Consumes: Task 2 draft compiler, Task 3 request sequence, and Task 4 verified context and transitions.
- Produces: `AttorneyDraftEvaluatorV22`, `EvaluationTelemetryEventV22`, `EvaluationTelemetrySinkV22`, `EvaluationDriverOutcomeV22`, `initialize_evaluation_v22()`, `resume_evaluation_v22()`, `next_evaluator_request_v22()`, `preflight_evaluator_response_v22()`, `guarded_submit_evaluator_response_v22()`, `submit_evaluator_response_v22()`, `run_evaluation_v22()`, and `continue_evaluation_v22()`.

- [ ] **Step 1: Write workflow RED tests**

Require valid low-quality draft acceptance, exact fragment progression, one bad draft then fresh clarification, two bad drafts then pause, byte-identical tree across pause, later resume, crash resume, strict external refusal without terminalization, compiler/preflight disagreement pause, multi-fragment review/audit, and complete referee/grading lifecycles.

```python
@pytest.mark.asyncio
async def test_two_bad_internal_drafts_pause_without_changing_run(run: Path) -> None:
    before = tree_bytes(run)
    outcome = await continue_evaluation_v22(run, AlwaysInvalidDraftEvaluator())
    assert outcome.engine_paused is True
    assert outcome.exit_code == 6
    assert tree_bytes(run) == before
    assert next_evaluator_request_v22(run) == outcome.pending_request
```

- [ ] **Step 2: Run the workflow RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_workflow.py -q
```

Expected: collection fails because `attorney_v22_workflow` does not exist.

- [ ] **Step 3: Implement strict external submission**

`preflight_evaluator_response_v22()` and `guarded_submit_evaluator_response_v22()` accept only complete strict envelopes. Invalid values return `EXTERNAL_RESPONSE_INVALID`, write nothing, retain the pending call, and never invoke a stop transition.

- [ ] **Step 4: Implement the internal draft driver**

Use this interface and outcome shape:

```python
class AttorneyDraftEvaluatorV22(Protocol):
    async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
        raise NotImplementedError


@dataclass(frozen=True)
class EvaluationDriverOutcomeV22:
    state: EvaluationRunStateV22
    result: EvaluationResultV22 | None
    engine_paused: bool
    pause_reason_codes: tuple[str, ...] = ()
    pending_request: EvaluatorRequestV22 | None = None
    exit_code: int = 0
```

For each pending request, invoke attempt 1, compile, and strict-preflight. On `NeedsClarification`, create a genuinely fresh attempt-2 prompt with only the original request and safe codes. If attempt 2 cannot compile, return paused exit `6` without a write. Convert compiler/preflight disagreement to `EngineDefect` and pause without retrying an already compiled semantic response.

Define an optional telemetry sink that receives only protocol version, compiler-contract fingerprint, operation, opaque fragment identity, attempt number, normalization codes, clarification codes, pause count, and resume count. The default sink is a no-op. Tests must prove events contain no draft bytes, source/report excerpts, private paths, candidate identities, or provider secrets, and that sink failure cannot affect run state or verification.

- [ ] **Step 5: Implement run and resume**

```python
async def run_evaluation_v22(
    case: AttorneyEvaluationCase,
    evaluator: AttorneyDraftEvaluatorV22,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationDriverOutcomeV22:
    initialize_evaluation_v22(
        case,
        output_dir,
        seed_hex=seed_hex,
        generation_capsule_paths=generation_capsule_paths,
    )
    return await continue_evaluation_v22(output_dir, evaluator)


async def continue_evaluation_v22(
    run_dir: Path,
    evaluator: AttorneyDraftEvaluatorV22,
) -> EvaluationDriverOutcomeV22:
    context = load_verified_v22_context(run_dir)
    if context.manifest.compiler_contract_fingerprint != COMPILER_CONTRACT_FINGERPRINT_V22:
        raise EvaluationIntegrityError("EVALUATOR_V22_COMPILER_CONTRACT")
    while context.manifest.terminal_status is None:
        step = await _drive_pending_fragment_v22(run_dir, evaluator)
        if step.engine_paused:
            return step
        context = load_verified_v22_context(run_dir)
    return _completed_driver_outcome_v22(context)
```

Define `_drive_pending_fragment_v22()` to perform the exact two-attempt compile/preflight/commit sequence and `_completed_driver_outcome_v22()` to require a verified substantive result. `continue_evaluation_v22()` must verify compiler-contract equality before any evaluator call, reuse the exact request on disk, and never repeat an accepted fragment.

- [ ] **Step 6: Run focused and neighboring workflow gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_workflow.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_v21_workflow.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_v22_workflow.py tests/evaluation/test_attorney_v22_workflow.py src/regulatory_harvest/evaluation/__init__.py
PYTHONPATH=src ../../.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_v22_workflow.py
```

Expected: all pass.

- [ ] **Step 7: Commit recoverable workflow**

```bash
git add src/regulatory_harvest/evaluation/attorney_v22_workflow.py src/regulatory_harvest/evaluation/__init__.py tests/evaluation/test_attorney_v22_workflow.py
git commit -m "feat: pause and resume evaluator fragments"
```

---

### Task 6: Full CLI, Internal Adapter, and Retained Boundaries

**Files:**
- Modify: `src/regulatory_harvest/cli.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `scripts/attorney_eval_full.py`
- Modify: `scripts/harvest_skill.py`
- Modify: `tests/cli/test_eval_cli.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_evaluation_capsule_provenance.py`

**Interfaces:**
- Consumes: Task 5 public APIs and existing case/capsule/scripted-fixture loaders.
- Produces: explicit Protocol 2.2 init, strict next/preflight/submit/status/verify routing, `eval attorney resume`, scripted draft adapter, exit `6`, and read-only retained-protocol routing.

- [ ] **Step 1: Write CLI RED tests**

Require explicit `--protocol 2.2` initialization, unchanged default Protocol 2.1 initialization, strict fragment lifecycle, engine pause exit `6`, valid pending status/verify, successful later resume, no result fabrication, capsule provenance, path privacy, and refusal of every mutation command on 1.3, 2.0, and 2.1 runs.

```python
def test_protocol_22_public_run_pauses_and_resumes_same_pending_request(tmp_path, capsys) -> None:
    paused = main(v22_run_args(tmp_path, scripted="two-invalid-drafts.json"))
    assert paused == 6
    request_before = pending_request_bytes(tmp_path / "run")
    resumed = main(v22_resume_args(tmp_path, scripted="valid-continuation.json"))
    assert resumed in {0, 3, 4}
    assert request_before in accepted_request_history(tmp_path / "run")
```

- [ ] **Step 2: Run CLI RED selection**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py tests/scripts/test_evaluation_capsule_provenance.py -q -k 'protocol_22 or retained_protocol'
```

Expected: Protocol 2.2 options and resume command are absent.

- [ ] **Step 3: Add explicit experimental routing**

Add `--protocol {2.1,2.2}` with default `2.1` to `eval-init` and `eval attorney run`. Add `eval attorney resume --output RUN --scripted-responses FILE --json`. Detect existing run protocol before resume. Do not expose a Protocol 2.2 mechanical-stop command.

- [ ] **Step 4: Add the controlled internal draft adapter**

The adapter reads one scripted or provider-native semantic draft per prompt, verifies truthful provider/model/isolation metadata from controller configuration, and returns only the inner draft object. It never fabricates the strict outer response. The workflow compiler owns that envelope.

- [ ] **Step 5: Map public outcomes exactly**

- completed PASS: exit `0`;
- input or external strict response invalid: exit `2`;
- substantive INCONCLUSIVE: exit `3`;
- substantive FAIL: exit `4`;
- integrity invalid: exit `5`;
- nonterminal engine pause: exit `6` with `{"error":"evaluation_engine_paused","ok":false,"pending_call":"source-review-fragment-0001"}` and no result fields.

Status and verify on a valid paused run return their ordinary valid nonterminal exit and expose only phase, pending call identity, compiler-contract fingerprint, and manifest root.

- [ ] **Step 6: Run CLI, provenance, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py tests/scripts/test_evaluation_capsule_provenance.py tests/evaluation/test_attorney_v22_workflow.py -q
PYTHONPATH=src ../../.venv/bin/ruff check src/regulatory_harvest/cli.py src/regulatory_harvest/evaluation/attorney_cli.py scripts/attorney_eval_full.py scripts/harvest_skill.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py tests/scripts/test_evaluation_capsule_provenance.py
PYTHONPATH=src ../../.venv/bin/mypy src scripts/attorney_eval_full.py scripts/harvest_skill.py
```

Expected: all pass.

- [ ] **Step 7: Commit full-runtime routing**

```bash
git add src/regulatory_harvest/cli.py src/regulatory_harvest/evaluation/attorney_cli.py scripts/attorney_eval_full.py scripts/harvest_skill.py tests/cli/test_eval_cli.py tests/scripts/test_harvest_skill.py tests/scripts/test_evaluation_capsule_provenance.py
git commit -m "feat: expose recoverable evaluator protocol"
```

---

### Task 7: Standard-Library Portable Mirror and Differential Parity

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: the exact Protocol 2.2 wire contract, compiler-contract descriptor, transitions, and replay semantics from Tasks 1 through 6.
- Produces: isolated standard-library Protocol 2.2 strict lifecycle, internal draft-compiler conformance functions, exact replay, retained routing, and full/portable differential vectors.

- [ ] **Step 1: Write the portable differential RED matrix**

Add named rows for review/audit fragmentation, normalizations, clarification, pause, later resume, stable PASS/FAIL, outcome-sensitive INCONCLUSIVE, referee and grade fragments, partial resume at every phase, retained replay/mutation refusal, unknown protocol, cross-case/lane/dispute/batch/fragment swaps, compiler-contract tamper, aggregate/result reseal, symlink/path refusal, and transaction rollback.

Every row captures ordered command, exit, stdout, stderr, and complete tree bytes for full and `python3 -I -S` portable runners.

- [ ] **Step 2: Run the matrix RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_harvest_skill.py -q -k 'protocol_22_portable_parity'
```

Expected: portable returns unsupported protocol or mismatched Protocol 2.1 bytes.

- [ ] **Step 3: Implement one bounded portable mirror block**

Add exactly one marker `# Protocol 2.2 portable mirror`. Mirror strict models with bounded standard-library validators, canonical contract fingerprint, draft normalization, source fragments, downstream semantics, transaction ownership, replay reconstruction, status, verify, and terminal exit mapping. Do not copy provider adapter or network logic into the portable runner.

- [ ] **Step 4: Prove draft-compiler conformance without a public bypass**

Expose an internal test-only callable loaded from the portable module that accepts request bytes, draft bytes, and controller provenance and returns the compiled strict bytes or safe reason codes. Do not add a public command that writes drafts or bypasses strict preflight.

- [ ] **Step 5: Preserve retained protocols and storage safety**

Run exact 1.3, 2.0, and 2.1 status/verify/mutation refusal vectors. Add before/post-manifest failures, same-byte competitors, inode swaps, Windows ownership simulation, and post-commit replay failure at source-review, source-audit, referee, ordinary grade, contested grade, and result transitions.

- [ ] **Step 6: Run portable and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/cli/test_eval_cli.py tests/scripts/test_evaluation_capsule_provenance.py -q
PYTHONPATH=src ../../.venv/bin/ruff check scripts/attorney_eval_portable.py scripts/harvest_portable.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py
PYTHONPATH=src ../../.venv/bin/mypy src
python3 -I -S scripts/harvest_portable.py eval-init --help
python3 -I -S scripts/harvest_portable.py eval-verify --help
```

Expected: all tests and isolated help pass. Direct-script mypy must have zero new findings relative to the exact Task 7 base.

- [ ] **Step 7: Audit size and duplication**

Record the one-marker portable Protocol 2.2 line count, full-runtime Protocol 2.2 line count, duplicate `_v22_` function scan, and exact diff scope. Remove accidental copied branches or duplicate definitions before commit.

- [ ] **Step 8: Commit portable parity**

```bash
git add scripts/attorney_eval_portable.py scripts/harvest_portable.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py
git commit -m "feat: mirror recoverable evaluator portably"
```

---

### Task 8: Packaging, Templates, Documentation, and Deterministic Fixtures

**Files:**
- Create: `assets/attorney-evaluation-v22-response.template.json`
- Create: `tests/fixtures/attorney-eval-v22/stable/case.json`
- Create: `tests/fixtures/attorney-eval-v22/stable/responses/scripted-drafts.json`
- Create: `tests/fixtures/attorney-eval-v22/pause-resume/case.json`
- Create: `tests/fixtures/attorney-eval-v22/pause-resume/responses/initial-drafts.json`
- Create: `tests/fixtures/attorney-eval-v22/pause-resume/responses/resume-drafts.json`
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
- Consumes: complete full and portable Protocol 2.2 surfaces.
- Produces: exact package allowlist, canonical strict response template, direct runnable stable and pause/resume fixtures, and section-scoped operator documentation.

- [ ] **Step 1: Write package/template/docs RED tests**

Require all six Protocol 2.2 modules plus the template exactly once, builder failure if one is omitted, direct strict-model validation of the template, no trailing newline, and per-document current-protocol wording that does not rewrite retained 1.3/2.0/2.1 sections.

- [ ] **Step 2: Run focused RED**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py -q -k 'protocol_22 or evaluator_response_template'
```

Expected: missing package entries and template.

- [ ] **Step 3: Add package and template bytes**

Create one compact sorted seven-key strict envelope using operation `source_review_fragment`, schema `2.2`, empty payload, placeholder hash, truthful placeholder provenance, and no trailing newline. Add exact sorted manifest entries and a dedicated Protocol 2.2 missing-input build guard.

- [ ] **Step 4: Add direct committed fixtures**

The stable fixture must exercise multiple review and audit fragments, mixed referee outcomes including substantive unresolved, multiple ordinary batches per lane, contested grades, terminal replay, full/portable parity, and unchanged fixture bytes. The pause/resume fixture must pause after two invalid internal drafts, verify unchanged pending bytes, then resume from committed valid drafts to a substantive terminal result.

- [ ] **Step 5: Update public operator documentation**

Describe Protocol 2.2 as explicit experimental behavior, not default. Define semantic drafts, strict compiled responses, safe normalization, content-quality boundary, five-item fragments, exit `6`, pending-run resume, substantive terminal outcomes, and retained replay-only protocols. Preserve attorney-validation and no-benchmark caveats.

- [ ] **Step 6: Run package, fixture, and static gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py tests/cli/test_eval_cli.py -q
PYTHONPATH=src ../../.venv/bin/ruff check scripts/build_skill.py tests/scripts/test_build_skill.py tests/skill/test_skill_package.py tests/cli/test_eval_cli.py
PYTHONPATH=src ../../.venv/bin/mypy src
git diff --check
```

Expected: all pass.

- [ ] **Step 7: Build and audit one package locally**

Build the skill archive, assert sorted unique member names and Git-blob equality, extract cleanly, run full and isolated portable init/verify help, scan fixtures and docs for private paths/data, and verify old 1.3/2.0/2.1 template hashes are unchanged.

- [ ] **Step 8: Commit package and docs**

```bash
git add assets/attorney-evaluation-v22-response.template.json tests/fixtures/attorney-eval-v22 scripts/skill-package-files.txt scripts/build_skill.py README.md SKILL.md docs/evaluation.md references/attorney-evaluation.md tests/scripts/test_build_skill.py tests/skill/test_skill_package.py tests/cli/test_eval_cli.py
git commit -m "docs: package recoverable evaluator protocol"
```

---

### Task 9: Public Stress Gate and Independent Review

**Files:**
- Create: `tests/evaluation/test_attorney_v22_stress.py`
- Modify only if a traced public RED requires a test-first correction within the approved Protocol 2.2 scope.
- Create ignored evidence: `.superpowers/sdd/2026-08-19-evaluator-protocol-2-2/task-9-report.md`

**Interfaces:**
- Consumes: exact candidate implementation from Tasks 1 through 8.
- Produces: public stress evidence, full test/static/build/audit evidence, adversarial evidence, and independent review verdict. It does not change default protocol or run private evaluation.

- [ ] **Step 1: Add the 100-lifecycle deterministic stress matrix**

Generate seeded public-only source records and draft variants covering zero, one, five, six, 52, 128, and more-than-128 review proposals; zero, one, five, six, 21, and more-than-128 audit concerns; normalizable and clarification paths; all substantive terminal outcomes; pause/resume; crashes; and full/portable controls.

```python
@pytest.mark.parametrize("seed", range(100))
def test_protocol_22_internal_drafts_never_end_mechanically(seed: int, tmp_path: Path) -> None:
    full, portable = run_seeded_v22_lifecycle(seed, tmp_path)
    assert full.transcript == portable.transcript
    assert full.tree == portable.tree
    assert "MECHANICAL_RESPONSE_INVALID" not in full.strict_submission_diagnostics
    assert full.terminal_status != "INCONCLUSIVE_MECHANICAL"
```

- [ ] **Step 2: Run focused Protocol 2.2 gates**

```bash
PYTHONPATH=src ../../.venv/bin/pytest tests/evaluation/test_attorney_v22_models.py tests/evaluation/test_attorney_v22_drafts.py tests/evaluation/test_attorney_v22_requests.py tests/evaluation/test_attorney_v22_compiler.py tests/evaluation/test_attorney_v22_artifacts.py tests/evaluation/test_attorney_v22_workflow.py tests/evaluation/test_attorney_v22_stress.py tests/cli/test_eval_cli.py tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_evaluation_capsule_provenance.py -q
```

Expected: all pass with zero internal strict mechanical refusals for valid semantic drafts.

- [ ] **Step 3: Run the complete public repository gate**

```bash
PYTHONPATH=src ../../.venv/bin/pytest -q
PYTHONPATH=src ../../.venv/bin/ruff check .
PYTHONPATH=src ../../.venv/bin/mypy src
git diff --check
git status --short
```

Expected: all tests/static gates pass and tracked status is clean after the stress-test commit.

- [ ] **Step 4: Commit the stress suite**

```bash
git add tests/evaluation/test_attorney_v22_stress.py
git commit -m "test: stress recoverable evaluator protocol"
```

- [ ] **Step 5: Build twice from the exact detached commit**

Use two clean `git clone --no-local` checkouts of the exact commit. Build both archives and require identical SHA-256, size, sorted unique members, exact manifest membership, every archive member equal to its Git blob, clean extraction, and full plus isolated portable help.

- [ ] **Step 6: Run sealed repository and archive audits**

Pass the approved owner-marker path only as an opaque audit argument. Require zero automated repository, archive, privacy, path, secret, private-marker, and retained-template findings. Record the manual publication-authorization boundary without exercising it.

- [ ] **Step 7: Perform adversarial review**

Review every spec acceptance criterion against code and tests. Probe semantic compiler tolerance, content-quality acceptance, ambiguous evidence, cross-boundary tampering, pause tree identity, compatible-contract resume, all transition rollback sites, retained mutation refusal, and current-run default preservation.

- [ ] **Step 8: Obtain independent review**

An independent reviewer receives the spec, plan, exact diff, Task reports, focused/full outputs, build hashes, audit outputs, and adversarial probes. Any Critical or Important finding returns to the owning task with a fresh RED and full gate restart.

- [ ] **Step 9: Record the public decision**

The report must state one of:

- `PUBLIC GATE PASSED: PRIVATE GATE MAY BE SEPARATELY AUTHORIZED`; or
- `PUBLIC GATE NOT PASSED: PROTOCOL 2.2 REMAINS EXPERIMENTAL`.

Do not change the new-run default.

---

### Task 10: Separately Authorized Private Readiness Gate

**Files:**
- No tracked source changes.
- Append ignored public-safe evidence: `.superpowers/sdd/2026-08-19-evaluator-protocol-2-2/task-10-report.md`
- Write private artifacts only inside the governed private evaluation root.

**Interfaces:**
- Consumes: exact independently reviewed commit, exact package SHA-256, exact compiler-contract fingerprint, the previously verified generation capsule and candidate, approved opaque owner marker, and separate explicit owner authorization.
- Produces: one fresh Protocol 2.2 run, resumable if it reaches an engine pause, private terminal evidence, and a public-safe readiness receipt. It does not publish or change defaults.

- [ ] **Step 1: Stop unless separately authorized**

Require an explicit owner instruction after Task 9 passes. Approval of this plan is not approval to run Task 10.

- [ ] **Step 2: Bind the exact reviewed inputs**

Verify Git commit, clean status, package hash/member count/member bytes, installed bytes, compiler-contract fingerprint, qualification root, generation-capsule root, candidate report hash, frozen source hashes, prior-cycle aggregate, and private-root governance before initializing evaluation.

- [ ] **Step 3: Initialize exactly one fresh Protocol 2.2 run**

Use the existing verified candidate and generation capsule. Do not generate a replacement candidate, alternate case, or second run.

- [ ] **Step 4: Execute or resume until substantive terminal or owner stop**

Use bounded one-initial-plus-one-clarification per driver invocation. If the driver returns exit `6`, verify the unchanged pending run, record the safe pause receipt, correct only a compatible engine defect if one exists, and resume the same run after explicit controller authorization. Do not convert a pause to INCONCLUSIVE and do not initialize another run.

- [ ] **Step 5: Verify terminal evidence**

Require full and isolated status/verify parity, exact manifest and result fingerprints, complete role counts, no rejected-draft persistence, no private leakage, and a substantive result that reached grading. A substantive FAIL is completed evidence and is not retried.

- [ ] **Step 6: Record readiness without publication**

State either:

- `PRIVATE READINESS PASSED: SUBSTANTIVE RESULT VERIFIED`; or
- `PRIVATE READINESS NOT PASSED: EXPERIMENTAL ONLY`.

No push, PR, merge, tag, release, publication, visibility, benchmark, maturity, or default-protocol action is permitted without a later separate owner decision.

---

## Plan Completion Gate

Before implementation begins:

- the owner approves the Protocol 2.2 specification;
- the owner approves this implementation plan and task boundaries;
- execution uses either `superpowers:subagent-driven-development` or `superpowers:executing-plans`;
- each task starts from its exact parent commit and a clean tracked worktree;
- each task records RED, GREEN, static, scope, and review evidence;
- any interface change updates this plan before downstream implementation; and
- Task 10 remains separately authorized even if Tasks 1 through 9 pass.
