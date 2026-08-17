# Ledger Repair Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every source-only ledger role the same explicit, machine-readable invariant contract, then rebuild and run one newly bound designated publication evaluation.

**Architecture:** A single full-runtime helper returns the canonical invariant projection used by all three ledger request builders. The stdlib-only portable runtime mirrors that exact ordinary-JSON value, and differential tests lock request bytes and guarded submission behavior. Existing validators remain authoritative; the projection explains them but never replaces or weakens them.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, Ruff, mypy, stdlib-only portable runtime, deterministic ZIP builder.

## Global Constraints

- Preserve the stopped designated evaluation cycle identified by its private controller receipt byte-for-byte; never retry or mutate it.
- Do not change validator semantics, refusal codes, retry ceilings, repeated-diagnostic stopping, fresh-context requirements, or refusal atomicity.
- Keep all candidate reports, mappings, scores, private sources, and private paths outside the public repository and archive.
- Full and portable requests, diagnostics, accepted artifacts, and replay behavior must remain canonically equivalent.
- Historical runs replay under their existing request bytes; only newly initialized runs receive new request fingerprints.
- Do not push, open a PR, release, publish, or change repository visibility.
- After the implementation gate, run exactly one newly bound designated evaluation. Substantive FAIL blocks publication; mechanical or inconclusive completion permits only an explicitly experimental beta with no performance claim after every deterministic public gate passes.

---

### Task 1: Canonical full-runtime ledger invariant contract

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_ledger.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- Modify: `tests/evaluation/test_attorney_workflow.py`

**Interfaces:**
- Produces: `ledger_invariant_contract() -> dict[str, object]`
- Consumes: existing `validate_ledger`, `_build_ledger_request`, `_audit_ledger_request`, and `_repair_ledger_request`
- Contract key: `payload["ledger_invariant_contract"]`

- [ ] **Step 1: Write the failing contract-projection test**

Add `test_ledger_invariant_contract_matches_validator_boundary` to
`tests/evaluation/test_attorney_workflow.py`. Assert exact equality to the
approved design object, including:

```python
expected = {
    "schema_version": "1.1",
    "binding": {
        "case_fingerprint": "source_record.source_record_fingerprint",
    },
    "identity": {
        "ledger_ids": "unique",
        "gap_ids": "unique",
        "entry_gap_ids": "disjoint",
        "walk_order": "unique_contiguous_zero_based",
    },
    "relationships": {
        "targets": "known_ledger_ids",
        "self_reference": "forbidden",
        "trigger_link_categories": ["enforcement", "penalty"],
        "trigger_target_categories": ["requirement", "prohibition"],
    },
    "citations": {
        "source_ids": "known_retained_sources",
        "slices": "unique_exact_half_open",
        "quote": "exact_source_text",
        "operative_categories_require_exact_support": True,
        "operative_categories_forbid_commentary_only_support": True,
    },
    "required_fields": {
        "requirement_prohibition_right": ["actor", "object"],
        "deadline": ["timing"],
        "exception": ["conditions_or_exceptions"],
        "enforcement": [
            "enforcing_authority",
            "enforcement_route",
            "trigger_link",
        ],
        "penalty": ["consequence", "trigger_link"],
        "remedy": ["consequence"],
    },
    "materiality_rationale": {
        "minimum_word_tokens": 5,
        "forbidden_exact_normalized_values": [
            "critical",
            "high priority",
            "important",
            "material",
            "significant",
        ],
    },
    "repair_closure": {
        "resolve_every_initial_finding": "evaluator_attestation",
        "remaining_audit_request_fingerprint": (
            "deterministically_enforced"
        ),
        "complete_true_requires_full_recheck": "evaluator_attestation",
        "remaining_disputes": (
            "deterministically_enforced_transaction_ready_only"
        ),
    },
}
assert ledger_invariant_contract() == expected
```

Also construct all three full-runtime ledger requests and assert each payload
contains exactly this value once. Assert the two `evaluator_attestation` values
are not described as deterministic enforcement in instructions or docs.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_workflow.py -q \
  -k 'ledger_invariant_contract or audit_and_repair_contract'
```

Expected: collection or assertion failure because
`ledger_invariant_contract` and the new request payload key do not exist.

- [ ] **Step 3: Implement the immutable projection**

In `attorney_ledger.py`, add:

```python
def ledger_invariant_contract() -> dict[str, object]:
    """Return deterministic ledger rules and declared evaluator attestations."""
    return {
        # Return the exact object asserted in Step 1.
    }
```

The implementation must create fresh lists and dictionaries on every call so
callers cannot mutate shared state. Do not derive behavior from this object;
`validate_ledger` remains the authority.

Import the helper in `attorney_workflow.py`. Add
`"ledger_invariant_contract": ledger_invariant_contract()` to the payloads of
`_build_ledger_request`, `_audit_ledger_request`, and `_repair_ledger_request`.
Update their system instructions to require checking the supplied contract and,
for repair, explicitly require global walk-order renumbering, new-ID allocation,
relationship remapping, exact-citation rechecking, and full closure validation.

Update `attorney_artifacts.py` request noninterference verification to reconstruct
and compare the same contract for new requests. Add a genuine base-version
completed build/audit/repair replay fixture so historical request bytes remain
durably covered rather than being rewritten into a newly initialized run.
Require each run to use one consistent contract generation across all ledger
requests: absent, exact historical `1.0`, or exact current `1.1`. Reject mixed
contract generations even when every individual request is otherwise valid.

- [ ] **Step 4: Run full-runtime tests and static checks**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_workflow.py \
  tests/evaluation/test_attorney_ledger.py -q
.venv/bin/ruff check src/regulatory_harvest/evaluation/attorney_ledger.py \
  src/regulatory_harvest/evaluation/attorney_workflow.py \
  src/regulatory_harvest/evaluation/attorney_artifacts.py \
  tests/evaluation/test_attorney_workflow.py
.venv/bin/mypy src/regulatory_harvest/evaluation/attorney_ledger.py \
  src/regulatory_harvest/evaluation/attorney_workflow.py \
  src/regulatory_harvest/evaluation/attorney_artifacts.py
```

Expected: all pass.

- [ ] **Step 5: Prove no shared mutable contract state**

Add a test that mutates nested lists in one returned contract and asserts a
second return equals the pristine expected value. Run the Task 1 tests again.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/regulatory_harvest/evaluation/attorney_ledger.py \
  src/regulatory_harvest/evaluation/attorney_workflow.py \
  src/regulatory_harvest/evaluation/attorney_artifacts.py \
  tests/evaluation/test_attorney_workflow.py
git commit -m "feat: disclose closed ledger invariants"
```

---

### Task 2: Portable parity and stopped-shape repair regression

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: Task 1's exact `ledger_invariant_contract()` value and request payload key
- Produces: portable `_ledger_invariant_contract() -> JsonObject`
- Preserves: guarded full/portable response acceptance, refusal diagnostics, no-write behavior, and replay parity

- [ ] **Step 1: Write differential RED tests**

Extend `test_audit_and_repair_contract_packets_match_portable` and add a build-
request counterpart. Assert:

```python
assert full_request == portable_request
assert full_request["payload"]["ledger_invariant_contract"] == (
    ledger_invariant_contract()
)
```

Add `test_stopped_shape_repair_contract_advances_full_and_portable` using only
fictional public-safe source text. The fixture must include an initial audit with
an add, an edit, a split, and relationship changes. The repaired ledger must:

- allocate new IDs for added and split entries;
- replace every stale relationship target;
- use unique contiguous zero-based `walk_order` values;
- preserve exact half-open source citations;
- satisfy every category-required field and concrete materiality rationale;
- bind `remaining_audit.request_fingerprint` to the repair request;
- return `complete=true` with no remaining disputes.

Assert both runtimes accept the response, seal byte-identical ledgers, advance
to the same first `grade_report` request, replay validly, and leave inputs
unchanged.

- [ ] **Step 2: Run the differential tests and verify RED**

```bash
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py -q \
  -k 'ledger_invariant_contract or stopped_shape_repair_contract'
```

Expected: failures because the portable request lacks the new contract and its
request fingerprint differs from full runtime.

- [ ] **Step 3: Mirror the contract in the portable runtime**

Add `_ledger_invariant_contract()` returning a fresh ordinary-JSON object with
the exact Task 1 bytes. Inject it into portable build, audit, and repair request
payloads. Mirror the full-runtime instruction text exactly. Do not import the
installed package or add third-party dependencies.

- [ ] **Step 4: Add adversarial write-free controls**

Parameterize the stopped-shape fixture with these single corruptions:

```python
[
    "duplicate_or_noncontiguous_walk_order",
    "unknown_relationship_target",
    "stale_split_relationship_target",
    "citation_offset_or_quote_mismatch",
    "missing_category_required_field",
    "generic_materiality_rationale",
    "wrong_remaining_audit_fingerprint",
]
```

For each, assert identical full/portable guarded refusal code and diagnostic
bytes, no repaired-ledger artifact, unchanged run-tree snapshot, and valid
replay of the pre-response state.

- [ ] **Step 5: Run portable, neighboring, and static gates**

```bash
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py -q
.venv/bin/pytest tests/scripts/test_harvest_skill.py \
  tests/evaluation/test_attorney_workflow.py \
  tests/evaluation/test_attorney_ledger.py -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
```

Expected: all pass.

- [ ] **Step 6: Commit Task 2**

```bash
git add scripts/attorney_eval_portable.py \
  tests/scripts/test_attorney_eval_portable.py \
  tests/scripts/test_harvest_skill.py
git commit -m "feat: mirror ledger repair invariants"
```

---

### Task 3: Public contract, package, and exact-commit verification

**Files:**
- Modify: `references/attorney-evaluation.md`
- Modify: `docs/evaluation.md`
- Modify: `tests/scripts/test_build_skill.py`
- Verify unchanged unless a failing allowlist test proves otherwise: `scripts/skill-package-files.txt`

**Interfaces:**
- Consumes: Task 2's full/portable runtime and test behavior
- Produces: public operator guidance and a reproducible archive containing the changed runtimes

- [ ] **Step 1: Write static/package RED tests**

Add an assertion that the installed reference explains:

```text
Every build, audit, and repair request carries the same versioned
ledger_invariant_contract. It is explanatory input; deterministic validation
remains authoritative. Repairs must globally recheck IDs, walk order,
relationships, citations, category fields, materiality, and audit binding.
```

Extend the two-clean-archive test to assert the changed full and portable files
are byte-identical to the repository files in both ZIPs and both extractions.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py \
  -q -k 'ledger or invariant or reproducible or archive'
```

Expected: static guidance assertion fails before documentation changes.

- [ ] **Step 3: Update public documentation**

Document the shared contract, unchanged fail-closed behavior, new-run-only
fingerprint effect, and prohibition on using detailed rejected-response content
for repairs. Do not include the private stopped-cycle facts or paths.

- [ ] **Step 4: Run complete public verification**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
.venv/bin/python scripts/quick_validate_skill.py
```

Build twice from two detached `git clone --no-local` exact-commit trees. Require
same member list, member bytes, ZIP bytes, file count, size, and SHA-256. Run ZIP
integrity, manifest equality, full help, `python3 -I -S` portable help, release
audit, and private-path/owner-marker scans.

- [ ] **Step 5: Commit Task 3**

```bash
git add references/attorney-evaluation.md docs/evaluation.md \
  tests/scripts/test_build_skill.py
git commit -m "docs: publish ledger repair contract"
```

If `scripts/skill-package-files.txt` required no edit, leave it untouched and
record that fact in the task report.

---

### Task 4: Fresh immutable qualification and designated gate

**Files:**
- Create only inside a new private cycle under the approved private evaluation
  root; never serialize that absolute root into a public artifact.
- Update public-safe ignored reports only under this plan's SDD workspace
- Do not modify public production code or the preserved stopped cycle

**Interfaces:**
- Consumes: exact reviewed commit, reproducible archive SHA-256, recoverable install, approved source receipts, and approved designated comparator selector
- Produces: fresh schema-1.1 qualification roots and one terminal designated evaluation receipt

- [ ] **Step 1: Bind the exact build**

Record exact commit, archive SHA-256, 103-member manifest equality, install byte
equality, clean help output, audit result, and source-receipt hashes. Stop before
qualification if any binding differs.

- [ ] **Step 2: Requalify the frozen source sets**

Create new empty schema-1.1 source-only capsules. Use one fresh isolated role per
case, guarded submission only, full and isolated replay verification, and the
existing bounded mechanical-repair rule. Do not generate or evaluate until all
three are ADMITTED and independently reviewed.

- [ ] **Step 3: Run exactly one designated cycle**

Rehash commit/archive/install/qualification/source/comparator bindings
immediately before generation. Generate once against the designated case,
require `completed` and all three generation booleans true, then initialize the
evaluation exactly once. Use one fresh role per pending operation and guarded
submission only.

- [ ] **Step 4: Apply the final-run publication policy**

Require verified absolute PASS with critical recall `1.0`, weighted recall at
least `0.90`, claim precision at least `0.95`, all narrative-safety dimensions
passing, all deterministic-safety checks passing, and clean history/replay for
any positive internal-validation claim. A substantive FAIL blocks publication.
A mechanical or inconclusive stop may support only an explicitly experimental
beta after every deterministic public gate passes, with the incomplete private
evaluation disclosed and no performance claim. Do not start the other two cases
or a second designated cycle.

- [ ] **Step 5: Independent final review**

Dispatch one read-only reviewer to verify exact bindings, accepted/refused call
counts, refusal atomicity, terminal thresholds, replay roots, privacy boundary,
and public-safe report accuracy. Preserve all private artifacts locally.

- [ ] **Step 6: Prepare the publication handoff**

Produce the exact release-candidate commit/archive hash, deterministic gate
receipt, permitted claim language, known-limitations language, and the proposed
external publication action. Do not push, open a PR, release, or change
visibility until that final external action is explicitly confirmed.
