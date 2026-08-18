# Qualification Capsule Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a replay-sealed schema-1.1 qualification contract that binds immutable build identity, explicit language treatment, and truthful judgment execution metadata while preserving schema-1.0 replay.

**Architecture:** Extend the candidate-free qualification case and source record with a build binding and exact language-treatment coverage. Store schema-1.1 judgments in the existing `JudgeResponse` envelope so execution metadata is hashed by the capsule; mirror the behavior in the standard-library runtime and retain the old raw-judgment path only for schema 1.0.

**Tech Stack:** Python 3.11+, Pydantic, standard library JSON/SHA-256, pytest, Ruff, mypy, reproducible ZIP packaging.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-16-qualification-capsule-integrity-design.md` exactly.
- Use TDD: every production behavior begins with a failing test that fails for the intended missing behavior.
- Preserve schema-1.0 canonical request, response, manifest, receipt, status, verification, and replay bytes.
- Full and portable schema-1.1 behavior and diagnostics must be canonical-byte equivalent.
- Do not change report generation, report drafting, ledger construction, grading, refereeing, aggregation, or thresholds.
- Do not read or write private qualification data while implementing public code and tests.
- Use only fictional test data in Git.
- Preserve unrelated dirty documentation; stage only task files.
- Do not push, publish, open a pull request, change visibility, or install outside the active local skill directory.

---

### Task 1: Define and project the schema-1.1 source contract

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_admission.py`
- Modify: `tests/evaluation/test_attorney_qualification.py`

**Interfaces:**
- Produces: `QualificationBuildBinding`, `QualificationLanguageTreatment`, schema-1.1 `QualificationCase`, and a schema-1.1 source-record projection.
- Preserves: schema-1.0 case and source-record canonical bytes.

- [ ] **Step 1: Add failing model and source-record tests**

Add tests that require these exact contracts:

```python
class QualificationBuildBinding(StrictModel):
    commit: str  # ^[0-9a-f]{40}$
    archive_sha256: str  # ^[0-9a-f]{64}$


class QualificationLanguageTreatment(StrictModel):
    source_ids: list[str]  # nonempty, unique
    method: str  # nonblank
    rationale: str  # nonblank
    limitations: str | None = None  # optional nonblank
```

The schema-1.1 case must require `build_binding` and `language_treatments`; treatment rows must cover every case source exactly once. Schema 1.0 must reject those fields and retain its current dump. Add malformed, duplicate, unknown, missing-coverage, unhashable, and `model_copy`/`model_construct` bypass cases.

- [ ] **Step 2: Run RED**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_qualification.py -q -k 'schema_1_1 or build_binding or language_treatment or legacy_1_0'
```

Expected: failures because the new models/version/projection do not exist; existing legacy controls pass.

- [ ] **Step 3: Implement minimal strict models and validation**

Add the two strict models. Change `QualificationCase.schema_version` to `Literal["1.0", "1.1"]`, add optional fields whose validator enforces:

```text
1.0 -> build_binding is absent and language_treatments is empty
1.1 -> build_binding is present and every source_id appears in exactly one treatment row
```

Round-trip revalidate typed nested values so validation-bypassing objects fail closed.

- [ ] **Step 4: Implement conditional source projection**

Keep the existing seven source-record keys for schema 1.0. For schema 1.1, add exactly:

```json
{"build_binding":{"archive_sha256":"…","commit":"…"},"language_treatments":[…]}
```

Update `build_admission_request` to accept only the exact key set for the selected schema and include the new fields in `source_record_fingerprint`, payload, request fingerprint, and safe metadata. Update the system instructions to require the language check to assess the supplied treatment and its limitations.

- [ ] **Step 5: Run GREEN and legacy frozen checks**

Run the RED selector plus all qualification/admission tests. Assert an explicit frozen schema-1.0 request fingerprint and canonical bytes before committing.

- [ ] **Step 6: Commit**

Stage only the three Task 1 files and commit:

```bash
git commit -m "feat: bind qualification source metadata"
```

---

### Task 2: Seal the schema-1.1 response envelope in the full runtime

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_qualification.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_cli.py`
- Modify: `scripts/attorney_eval_full.py`
- Modify: `tests/evaluation/test_attorney_qualification.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: schema-1.1 case/source contract from Task 1.
- Produces: version-directed qualification response parsing and replay using `JudgeResponse` for 1.1 and raw `CaseAdmissionJudgment` for 1.0.

- [ ] **Step 1: Add failing lifecycle and tamper tests**

Create fictional schema-1.1 cases and assert:

- `eval-qualify-next` requests the outer response envelope while its `payload` remains the existing admission judgment;
- `eval-qualify-submit` accepts an exact envelope and stores the entire canonical envelope in `admission-response.json`;
- the artifact hash and root change when provider, model, isolation, commit, archive, or language treatment changes;
- replay rejects post-submission tampering of every new field;
- raw inner judgments, mismatched operation/fingerprint, blank provider/model, invalid isolation, extra keys, noncanonical JSON, missing files, excessive size/depth, and unhashable values fail without state mutation;
- a schema-1.0 capsule retains the old raw response and exact frozen root/receipt bytes.

- [ ] **Step 2: Run RED**

Run:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_qualification.py tests/scripts/test_harvest_skill.py -q -k 'qualification and (schema_1_1 or response_envelope or build_binding or language_treatment or legacy_1_0)'
```

Expected: schema-1.1 lifecycle/envelope tests fail at current raw-response parsing; legacy controls pass.

- [ ] **Step 3: Implement version-directed response parsing**

For schema 1.1:

1. Parse `JudgeResponse` strictly.
2. Require `operation == admit_case` and exact request fingerprint.
3. Parse `payload` as `CaseAdmissionJudgment` and require its request fingerprint too.
4. Store canonical bytes for the full envelope.
5. Keep `judgment_fingerprint` bound to the inner judgment while the response artifact hash binds the envelope.

For schema 1.0, retain the existing parser and stored bytes.

- [ ] **Step 4: Make replay version-aware**

Replay must load the case first, choose the corresponding response grammar, revalidate the complete envelope, extract/revalidate the inner judgment, recompute readiness/receipt/manifest, and compare canonical bytes. Keep the existing status and verification output shapes unchanged; the case artifact, source-record fingerprint, and manifest root provide the sealed build binding.

- [ ] **Step 5: Add guarded CLI boundary parity**

Use existing bounded input/response/integrity error envelopes. Require the same stable diagnostic for every schema-1.1 invalid vector and verify zero writes on refusal.

- [ ] **Step 6: Run GREEN and neighboring evaluator tests**

Run the RED selector, all qualification tests, evaluator CLI tests, generation tests, and legacy replay tests.

- [ ] **Step 7: Commit**

Stage only the five Task 2 files and commit:

```bash
git commit -m "feat: seal qualification judge context"
```

---

### Task 3: Mirror schema 1.1 in the standard-library runtime

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`

**Interfaces:**
- Consumes: full-runtime schema-1.1 canonical behavior from Tasks 1–2.
- Produces: standard-library parsing, submission, storage, status, replay, and diagnostics with exact full-runtime parity.

- [ ] **Step 1: Add failing differential tests first**

For each valid and invalid schema-1.1 case and response vector, run both full and `python3 -I -S` portable surfaces. Assert exact stdout, stderr, exit code, stored artifact bytes, manifest/root, receipt, status, verification, and no-mutation parity. Include Unicode method/rationale/limitations, CRLF source text, missing/duplicate treatments, malformed hashes, all judge-isolation values, envelope tampering, and validation-bypassing mappings.

- [ ] **Step 2: Run RED**

Run:

```bash
.venv/bin/pytest tests/scripts/test_attorney_eval_portable.py tests/scripts/test_harvest_portable.py tests/scripts/test_harvest_skill.py -q -k 'qualification and schema_1_1'
```

Expected: portable parsing or canonical output differs from the green full runtime.

- [ ] **Step 3: Implement strict portable case/source validation**

Mirror the exact schema-version branching, field sets, hash patterns, language-treatment coverage, sorting, source-record projection, and request construction. Do not add permissive coercions absent from full Pydantic behavior.

- [ ] **Step 4: Implement portable envelope storage and replay**

Mirror the full runtime's envelope validation, inner judgment snapshot, canonical response bytes, artifact/judgment fingerprints, manifest construction, status, and verification. Legacy schema 1.0 must remain on the raw-judgment path.

- [ ] **Step 5: Run GREEN and adversarial parity**

Run the RED selector, entire portable evaluator suite, full/portable workflow tests, malformed model-boundary matrices, and explicit V1 replay tests.

- [ ] **Step 6: Commit**

Stage only the five Task 3 files and commit:

```bash
git commit -m "feat: mirror sealed qualification capsules"
```

---

### Task 4: Ship the contract and restart the bounded qualification cycle

**Files:**
- Modify: `assets/attorney-evaluation-qualification.template.json`
- Modify: `references/attorney-evaluation.md`
- Modify: `docs/evaluation.md`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/skill/test_skill_package.py`
- Modify only if required by exact member diff: `scripts/skill-package-files.txt`
- Private create: one new publication-qualification cycle outside Git.

**Interfaces:**
- Consumes: schema-1.1 full/portable runtime.
- Produces: packaged fictional template, accurate proof-boundary documentation, reproducible installed archive, and a new three-case source-only qualification cycle.

- [ ] **Step 1: Add failing package/template/documentation tests**

Require the shipped template to contain fictional schema-1.1 build binding and complete fictional language-treatment coverage. Require docs to state that provider/model/isolation are sealed attestations, not independent execution proof. Require both clean-extracted runtimes to initialize, submit, status, and verify the materialized template with identical bytes.

- [ ] **Step 2: Run RED**

Run:

```bash
.venv/bin/pytest tests/scripts/test_build_skill.py tests/skill/test_skill_package.py tests/scripts/test_harvest_skill.py -q -k 'qualification or package or template'
```

Expected: template/docs/package assertions fail before edits.

- [ ] **Step 3: Update public contract surfaces**

Use only fictional values. Explain schema 1.1, required build/language metadata, response envelope, legacy replay, and the exact proof boundary. Keep the attorney-review disclaimer unchanged.

- [ ] **Step 4: Run complete public verification**

Run:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
git diff --check
git diff --cached --check
```

Then build twice from separate detached no-local clones, require byte identity, ZIP integrity, exact manifest members, release audit `ok: true`, zero automated privacy findings, full help, and isolated portable help.

- [ ] **Step 5: Commit the public contract**

Stage only Task 4 public files and commit:

```bash
git commit -m "docs: publish qualification capsule integrity"
```

- [ ] **Step 6: Independently review the complete patch**

Require one task review after each task and one whole-range review after Task 4. Resolve Critical and Important findings through the bounded review loop. Record deferred Minors with rationale.

- [ ] **Step 7: Restart qualification exactly once**

Create a new private cycle. Retain the stopped prior cycle unchanged. Freeze the reviewed commit, retain one of the two exact verified archives in the new cycle, install it recoverably, create three new schema-1.1 case versions, and run one fresh source-only judgment per case. Use at most three mechanical attempts and stop on a repeated diagnostic. Do not generate a report until all three capsules are `ADMITTED` and replay-valid with matching build binding and explicit language treatment.

- [ ] **Step 8: Return to publication qualification**

If all three cases pass, resume Task 4 of `docs/superpowers/plans/2026-08-14-publication-qualification.md` at the designated substantive gate. Otherwise write the bounded terminal defect receipt and stop without another implementation or candidate cycle.
