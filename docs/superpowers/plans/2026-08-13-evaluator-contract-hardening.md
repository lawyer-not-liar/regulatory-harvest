# Evaluator Contract Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the automated attorney evaluator, refresh the private India currentness record, install the corrected local skill, and complete a fresh sealed three-case suite without publishing anything.

**Architecture:** Separate lightweight initial ledger-audit findings from strict unresolved transactions, expose deterministic role-response contracts, add a read-only preflight command, and align material-exception finding semantics with partial coverage. Mirror every behavior in the packaged standard-library evaluator and keep all legal source packets and comparison artifacts private.

**Tech Stack:** Python 3.11+, Pydantic public core, standard-library portable evaluator, pytest, Ruff, mypy, reproducible ZIP packaging, immutable evaluation capsules.

## Global Constraints

- Preserve the source-only ledger, anonymous grading, exact-source, capsule-parity, and immutable-run boundaries.
- `remaining_audit` must remain transaction-ready before sealing or refereeing.
- `eval-preflight` must be byte-for-byte read-only and must use the same semantic validation as `eval-submit`.
- Full and portable engines must remain behaviorally and artifact compatible.
- Repository tests use only synthetic public material.
- India legal sources, legacy reports, candidate reports, mappings, and results remain in the private evaluation workspace.
- Do not publish, push, open a pull request, mutate a terminal run, or alter unrelated dirty files.
- Preserve this exact legal-use disclaimer: `Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.`

---

## Task 1: Capture the two regressions as failing tests

**Files:**
- Modify: `tests/evaluation/test_attorney_ledger.py`
- Modify: `tests/evaluation/test_attorney_grading.py`
- Modify: `tests/evaluation/test_attorney_workflow.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`

- [ ] Add a synthetic initial-audit response whose precise `add` and `split`
  findings omit proposed entries and assert that it should advance to ledger
  repair.
- [ ] Add the corresponding remaining-audit test asserting that the same
  non-transaction payload cannot be sealed.
- [ ] Add a material exception entry graded `PARTIAL` with
  `MATERIAL_EXCEPTION_MISSING` and assert that it is valid, while non-exception
  and supporting-entry cases remain invalid.
- [ ] Run the focused tests and record the expected RED failures:

```bash
.venv/bin/pytest tests/evaluation/test_attorney_ledger.py tests/evaluation/test_attorney_grading.py tests/evaluation/test_attorney_workflow.py tests/scripts/test_attorney_eval_portable.py -q
```

## Task 2: Split initial and remaining audit validation

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_ledger.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_artifacts.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Modify: `scripts/attorney_eval_portable.py`

- [ ] Add a finding-level validator for the complete initial audit.
- [ ] Keep `ledger_disputes` strict for repaired remaining audits, sealing, and
  referee application.
- [ ] Route initial submission and replay verification through finding-level
  validation; route remaining audit through strict transaction validation.
- [ ] Add a deterministic `audit_action_contract` to audit and repair packets
  and update the role instructions.
- [ ] Make full and portable packets, validation results, and replay behavior
  match.
- [ ] Run the Task 1 tests and require GREEN.

## Task 3: Align grade finding contexts and expose the contract

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_grading.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `tests/evaluation/test_attorney_grading.py`
- Modify: `tests/evaluation/test_attorney_workflow.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`

- [ ] Permit `MATERIAL_EXCEPTION_MISSING` for `MISSING` or `PARTIAL` material
  and critical exception entries only.
- [ ] Add the deterministic `finding_code_contract` to every grade packet.
- [ ] Improve invalid-context diagnostics so they identify the ledger entry and
  finding code without revealing another report or candidate identity.
- [ ] Run focused grading and parity tests and require GREEN.

## Task 4: Add a read-only full and portable preflight command

**Files:**
- Modify: `src/regulatory_harvest/evaluation/attorney_models.py`
- Modify: `src/regulatory_harvest/evaluation/attorney_workflow.py`
- Modify: `src/regulatory_harvest/evaluation/__init__.py`
- Modify: `scripts/attorney_eval_full.py`
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/evaluation/test_attorney_workflow.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_harvest_portable.py`

- [ ] Write RED tests for valid and invalid `eval-preflight` and for no run-byte
  changes before and after preflight.
- [ ] Implement one canonical preflight result shape and exit-code behavior.
- [ ] Reuse the exact accepted-transition semantic validator without committing
  calculated artifacts.
- [ ] Prove full and portable output parity and that a subsequently submitted
  preflighted response advances normally.
- [ ] Run focused workflow and command tests and require GREEN.

## Task 5: Update the universal skill instructions

**Files:**
- Modify: `SKILL.md`
- Modify: `references/attorney-evaluation.md`
- Modify: `README.md`
- Modify: `docs/evaluation.md`
- Modify: `tests/skill/test_skill_package.py`

- [ ] Require internal preflight before every evaluation response submission.
- [ ] Explain initial findings versus strict remaining disputes without exposing
  JSON or command operation to attorneys.
- [ ] Preserve the fully automated one-request journey and exact disclaimer.
- [ ] Run skill-content and documentation contract tests.

## Task 6: Run the development verification loop

- [ ] Run all evaluator, runner, skill, and package tests.
- [ ] Run the complete repository test suite.
- [ ] Run Ruff and mypy.
- [ ] Run an independent adversarial review of the complete diff and resolve
  every load-bearing finding.
- [ ] Confirm `git diff --check` and verify that the pre-existing dirty files
  remain untouched.

## Task 7: Research and lock the private India currentness packet

**Private files only:**
- Create a new source capture under the new private suite root.
- Create a new case fixture and generation inputs under that root.

- [ ] Read the Regulatory Harvest currentness and security protocols.
- [ ] Search official Indian primary sources for DPDP Act and Rules status,
  commencement, amendment, corrigendum, repeal, and supersession evidence
  through 2026-07-17.
- [ ] Retain exact official bytes with canonical URL, source role, language,
  access date, and relationship metadata.
- [ ] Independently check that the refreshed packet answers the admission
  currentness question without relying on either report.
- [ ] Keep the source capture and case outside the repository and ZIP.

## Task 8: Build, audit, and install the private candidate

- [ ] Build the universal ZIP twice and require byte identity.
- [ ] Run the release privacy audit and archive tests.
- [ ] Extract to a fresh staging directory and validate the staged skill.
- [ ] Preserve a recoverable backup of the installed local skill.
- [ ] Replace only `<user-skills-dir>/regulatory-harvest` with the
  verified staged tree and prove byte parity.
- [ ] Run an installed-skill synthetic research smoke test and evaluator
  preflight smoke test.

## Task 9: Run a new sealed three-case comparison suite

- [ ] Create a new private run root; do not reuse or edit either prior terminal
  run.
- [ ] Build two verified generation capsules per matter from the same exact
  question, source bytes, client-fact bytes, and generation instructions.
- [ ] Verify every generation capsule with `ok:true` before evaluation.
- [ ] Initialize France, India, and United Kingdom comparison cases with fresh
  seeds and capsule-proven parity.
- [ ] For every role, use a fresh context, canonical response, successful
  `eval-preflight`, and then `eval-submit`.
- [ ] Continue independent cases after substantive `FAIL`, `CASE_INVALID`, or
  `INCONCLUSIVE`; stop on integrity failure.
- [ ] Run `eval-verify` for every terminal case and require `ok:true`.

## Task 10: Final receipt and handoff

- [ ] Write a private final receipt containing build hash, capsule hashes,
  terminal dispositions, absolute and comparative outcomes, matrix paths,
  currentness findings, baseline-preservation hash, and verification results.
- [ ] Re-run the offline guard.
- [ ] Confirm no publication, push, pull request, or public artifact write.
- [ ] Report the outcome and evidence-level matrix paths without exposing
  blinded mappings or internal role packets.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
