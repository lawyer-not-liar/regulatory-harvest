# Regulation Title and Requirements Boundary Verification

Date: 2026-08-11

## Scope

This verification covers named regulation titles, the semantic boundary between
legal requirements and implementation advice, full and dependency-free engine
parity, universal packaging, the installed local skill, and a fresh private
formative comparison. It does not authorize publication or establish legal
correctness, completeness, applicability, or currentness.

## Public implementation gates

From the isolated `codex/universal-skill` worktree:

```text
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/validation/test_bundle.py tests/analysis/test_report.py tests/scripts/test_harvest_portable.py tests/analysis/test_report_parity.py tests/combine/test_stages.py tests/skill/test_skill_package.py tests/e2e/test_skill_flow.py -q
157 passed

.venv/bin/pytest -q -rs
368 passed, 1 skipped

.venv/bin/ruff check .
All checks passed!

.venv/bin/mypy src
Success: no issues found in 54 source files

python3 scripts/audit_release.py --json
automated findings: none
manual requirement: MANUAL_CONFIRMATION_REQUIRED

git diff --check
clean
```

The intentional skip is the live Cite adapter check, which requires external
service environment variables. It is not counted as completed local coverage.

## Sequential adversarial review

Implementation, code review, adversarial review, and evaluator review were
performed sequentially because delegation was not authorized. The review checked:

- blank and absent matter titles, including backward compatibility for old
  unprofiled bundles;
- direct and nested purpose violations in Key Requirements and Implementation
  Workplan;
- exact full-versus-portable issue parity, including multiple simultaneous
  errors and stable ordering;
- duplicate-issue and false-positive risk;
- absence states and the separation of exact quotations into the audit; and
- the packaged template used by extracted installations.

The adversarial subset passed 115 tests. Full and portable validation produced
byte-for-byte equivalent structured issues in the multi-error scenario. No open
Critical or Important finding remained.

## Reproducible universal package

Two clean builds were byte-identical. The verified artifact is:

```text
path: dist/regulatory-harvest-skill.zip
archive root: regulatory-harvest/
file count: 79
size: 176171 bytes
SHA-256: 8f75e64a01081a29b6719e22231405541045586568de01f4c7339e75f16cabec
unzip -t: no errors
```

The extracted package passed the skill validator and release audit. It contains
no tests, caches, Git state, worktrees, private evaluation artifacts, internal
plans, or nested distribution output.

## Installed local skill

The previous installed skill was retained in a temporary rollback location
while a clean staged extraction was installed. The staged and installed package
trees compared byte-for-byte before execution. The installed skill contains the
same 79 allowlisted release files; the smoke run subsequently created only local
Python interpreter caches.

With site packages and package-index access disabled, the installed
dependency-free runner completed a synthetic provided-only matter with:

```text
status: completed
valid: true
evidence precision: valid
provision recall: valid
blocking review items: 0
coverage issues: 0
report H1: named regulation
Key Requirements: legal rule
Implementation Workplan: operational action
exact quotation in report: absent
exact quotation in audit: present
```

## Private formative comparison

The private evaluator remained local and offline. A fresh depth-validation round
was selected from the full preserved evidence corpus while excluding the root
comparison and every prior sealed selection. Selection verification established:

```text
smoke cases: 1
scored cases: 3
evidence corpus mode: full-preserved
source parity: true
prior record reuse: none
client-fact parity: disclosed per case
```

The smoke case completed before scored drafting. All three scored reports then
completed with valid evidence-precision and provision-recall gates, zero blocking
reviews, and zero coverage issues. Each uses the regulation name as H1, expresses
Key Requirements as provision-centered legal rules, separates the implementation
response, and retains direct penalties and enforcement treatment.

The legacy comparators remained unavailable during new-report generation. After
all three new reports were terminal, only their three frozen comparators were
written and the generation set was immediately sealed. The round verifier,
private project verifier, reviewer verifier, JSON validation, JavaScript syntax
check, table-rendering tests, exact-disclaimer check, preservation comparison,
and offline guard passed.

The private reviewer is running on `127.0.0.1` with three cases, a 45-minute
target, zero initial progress, independent Report A and Report B ratings, and a
side-by-side preference step. Its fragment token and answer key remain private.

## Boundaries and remaining gates

- The comparison is a formative single-reviewer exercise, not a statistical
  validation study.
- Currentness and legal accuracy still require attorney review against the
  governing authority.
- The skipped live-service check remains external and credential-dependent.
- No private report, source, rating, record identifier, answer-key mapping, or
  client fact is included in this repository.
- No remote, push, merge, pull request, package publication, release, or public
  announcement was created.
- Publication remains behind manual ownership, confidentiality, licensing, and
  authorization review.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
