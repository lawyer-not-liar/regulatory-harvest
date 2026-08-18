# Evaluation Generation Capsule Implementation Plan

> **For agentic workers:** use subagent-driven development, TDD, fresh adversarial review, and verification before completion.

**Goal:** Replace self-attested candidate access receipts with a runner-issued,
immutable local generation sequence that binds exact inputs to the submitted
report and supports honest formal-comparison admission.

**Constraints:** standard-library portable substrate; no provider calls, API
keys, MCP, database, or service; no public/private data crossing; no push,
publish, or merge; outer generation/evaluation response envelopes remain `1.0`.

## Task 1: Standard-library capsule substrate and full/portable commands

Create `src/regulatory_harvest/evaluation/attorney_generation.py` as a
dependency-free module and add the five `eval-gen-*` commands to both runners.
Implement the schema, retained no-follow capture, immutable state machine,
canonical artifacts, manifest/root verification, and stable exits described in
the design. The portable runner must dynamically load the same standard-library
module under isolated Python rather than carry a second algorithm.

Use TDD for schema/type strictness, exact bytes, nonce/request binding,
duplicate/out-of-order transitions, resume, all filesystem attacks, inventory
and artifact tampering, platform boundaries, full/portable byte parity, and
isolated standard-library execution. Commit separately.

## Task 2: Case schema 1.1 and comparative provenance gate

Replace filesystem `access_receipt_path` with the strict
`generation_capsule_path`/`external_report_path` candidate shape. New
initialization requires case schema `1.1`. Verify capsules before constructing
candidate models and copy a replay-checkable generation record plus capsule root
into the immutable case. Never derive provenance from the common packet.

Permit one external preserved report to enter absolute grading without claiming
source-access parity. Require verified matching capsules for a two-report formal
comparison; otherwise return the stable source-parity/comparator-access outcome
without a winner. Preserve read-only verification of retained legacy case
artifacts or reject them with the stable unsupported-schema result, as required
by the existing artifact-family policy.

Use TDD for capsule/common match, missing/extra/mismatched sources and client
facts, report/candidate mismatch, external one-report absolute evaluation,
external two-report suppression, legacy/mixed schema, full/portable parity,
resume, terminal artifacts, and requirement matrices. Commit separately.

## Task 3: Universal skill, templates, and real forward journey

Add public-safe generation input/response templates and update the evaluation
reference. For newly generated reports, the host runs each capsule automatically
before `eval-init`. For historical reports, the skill performs separate absolute
evaluations and reports that a formal winner is unavailable unless original
generation is rerun through a capsule.

Run a fresh two-capsule, two-report fictional host journey through terminal
evaluation with a nonempty provision matrix and both full/portable verification.
Run a fresh external-report journey proving no false formal comparison. Update
skill behavior tests and commit separately.

## Completion gate

- Fresh adversarial reviewers find no Critical or Important issues in each task.
- The original post-hoc receipt construction cannot enter new comparative
  evaluation.
- Full/portable focused and complete suites, Ruff, mypy, isolated import,
  release privacy scan, and extracted-package tests pass.
- The documentation states the local-sequence proof and malicious-host limit
  exactly.
