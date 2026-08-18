# Automated Attorney Evaluation Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make fully automated attorney evaluation available through the same self-contained Regulatory Harvest skill in Codex and Claude Desktop with one user request and no human rating workflow.

**Architecture:** Extend the universal skill with an evaluation recipe and a dependency-free role-packet runner. The deterministic runner creates blinded packets, validates host-authored judge responses, advances the state machine, and renders final results. Codex and Claude Desktop use the identical `SKILL.md`, assets, references, scripts, schemas, and scoring rules.

**Tech Stack:** Markdown Agent Skill, Python standard library portable runner, packaged Python core when dependencies are available, pytest subprocess tests, reproducible ZIP builder.

## Global Constraints

- Complete the Automated Attorney Evaluation Core plan first.
- Keep one skill, one self-contained release ZIP, and two installation methods.
- Require no MCP server, n8n workflow, SurrealDB service, database, model SDK, or API key.
- Let the host's configured model perform judge roles; keep deterministic checks and aggregation in Python.
- Expose one attorney-facing request; do not expose a browser reviewer, rating sequence, or reveal step.
- Preserve ledger-before-report isolation even in hosts that execute roles sequentially.
- Record `judge_isolation` honestly; never claim fresh-context isolation when unavailable.
- Keep private sources, legacy reports, answer keys, ratings, and case mappings outside the skill ZIP.
- Preserve full-engine and portable schema, issue-code, score, threshold, and artifact parity.
- Preserve the existing research journey and package reproducibility.
- Do not publish, push, merge, or contact an external service.

---

## File map

- Create `scripts/attorney_eval_portable.py`: reviewed standard-library
  evaluator substrate shared by the portable command surface.
- Create `tests/scripts/test_attorney_eval_portable.py`: strict schema,
  storage, transition, and full-core golden-vector conformance tests.
- Create `references/attorney-evaluation.md`: complete evaluation role sequence, rubric, and failure handling.
- Create `assets/attorney-evaluation-case.template.json`: public-safe strict case template.
- Create `assets/attorney-evaluation-response.template.json`: public-safe operation response envelope.
- Modify `SKILL.md`: add the one-request evaluation journey and route to the new reference.
- Modify `scripts/harvest_skill.py`: full-runtime role packet and state-machine commands.
- Modify `scripts/harvest_portable.py`: dependency-free equivalent.
- Modify `scripts/skill-package-files.txt`: allowlist the new reference and templates.
- Modify `scripts/audit_release.py`: scan evaluation assets and packaged outputs for private markers.
- Modify `tests/scripts/test_harvest_skill.py`: full-runtime evaluation command tests.
- Modify `tests/scripts/test_harvest_portable.py`: portable parity tests.
- Modify `tests/scripts/test_build_skill.py`: extracted-ZIP, allowlist, reproducibility, and private-boundary checks.
- Modify `tests/skill/test_skill_package.py`: skill-content and host-neutral instruction checks.
- Modify `README.md`: attorney-first automatic evaluation examples and the research/evaluation distinction.
- Modify `docs/release-checklist.md`: automated-evaluator release gates.

### Task 0: Dependency-free evaluator substrate and golden conformance

**Files:**
- Create: `scripts/attorney_eval_portable.py`
- Create: `tests/scripts/test_attorney_eval_portable.py`

**Interfaces:**
- Consumes: the public core's frozen `1.1` wire artifacts and CC0 synthetic
  fixture.
- Produces: standard-library-only schema validation, scoring, transition,
  immutable storage, and verification functions used by the portable runner.

The initial Task 1 feasibility audit established that the existing portable
runner's pathname-based research storage cannot safely implement evaluator
artifacts. Do not paste a weaker state machine into `harvest_portable.py`.
Build a separately reviewed substrate with these boundaries:

- exact canonical JSON, enum, issue-code, materiality, scoring, threshold,
  fingerprint, artifact-name, transition, and terminal-exit parity with the
  public core;
- retained-root descriptor-relative POSIX traversal, `O_NOFOLLOW` on every
  component, ordinary-file checks, pre/post identity checks, immutable artifact
  creation, durable atomic manifest/state replacement, and fail-closed handling
  of link, replacement, inventory, cleanup, and mixed-version failures;
- no pathname fallback after the root is opened;
- a stable unsupported-platform integrity result on Windows until the native
  portable handle backend receives live verification; and
- no imports outside the Python 3.11 standard library.

Golden conformance tests must run the full core and portable substrate from the
same case, seed, and canonical judge responses and require byte equality for
`case-readiness.json`, `legal-ledger.json`, `evaluation-result.json`, and
`evaluation-report.md`. Add differential vectors for every admission code,
entry and narrative finding, threshold boundary, comparison result, repair,
referee path, terminal phase, invalid response, and tamper class. Tests must
also cover symlink components, root/leaf replacement races, nonregular files,
duplicate/out-of-order submissions, interruption at every phase, and read-only
verification.

Use TDD, run the focused evaluation and portable suites plus Ruff and mypy, and
commit the substrate separately before Task 1 command routing.

### Task 1: Portable evaluation schema and role-packet commands

**Files:**
- Modify: `scripts/harvest_skill.py`
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/scripts/test_harvest_portable.py`

**Interfaces:**
- Consumes: public core models and deterministic workflow from the completed core plan.
- Produces these identical full and portable commands:
  - `eval-init --case CASE --run RUN --seed-hex SEED`
  - `eval-next --run RUN`
  - `eval-submit --run RUN --response RESPONSE`
  - `eval-status --run RUN`
  - `eval-verify --run RUN`

- [ ] **Step 1: Write failing full and portable command-contract tests**

```python
@pytest.mark.parametrize("runner", [SKILL_RUNNER, PORTABLE_RUNNER])
def test_eval_init_creates_source_only_admission_packet(runner: Path, tmp_path: Path) -> None:
    result = run_runner(
        runner,
        "eval-init",
        "--case", str(FIXTURE / "case.json"),
        "--run", str(tmp_path / "run"),
        "--seed-hex", "3" * 64,
    )
    assert result.returncode == 0, result.stderr
    packet = json.loads((tmp_path / "run" / "next-request.json").read_text())
    assert packet["operation"] == "admit_case"
    serialized = json.dumps(packet)
    assert "report_text" not in serialized
    assert "regulatory_harvest" not in serialized.casefold()
```

Add a parity test that feeds the same scripted responses through both runners and
asserts byte equality for `case-readiness.json`, `legal-ledger.json`,
`evaluation-result.json`, and `evaluation-report.md`.

- [ ] **Step 2: Run focused runner tests and verify red**

Run: `.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -k 'eval_' -q`

Expected: FAIL because evaluation commands are not registered.

- [ ] **Step 3: Add full-runtime commands using the public workflow**

Register the five subcommands in `scripts/harvest_skill.py`. `eval-next` writes
and returns one strict `JudgeRequest` without invoking a model. `eval-submit`
validates one `JudgeResponse`, advances the run, and writes the next packet or
final disposition.

Use stable status codes:

```python
EVAL_EXIT_SUCCESS = 0
EVAL_EXIT_INPUT = 2
EVAL_EXIT_INCONCLUSIVE = 3
EVAL_EXIT_FAIL = 4
EVAL_EXIT_INTEGRITY = 5
```

- [ ] **Step 4: Implement the same dependency-free behavior**

Mirror the public `1.1` evaluation schemas and deterministic algorithms in focused standard-
library sections of `scripts/harvest_portable.py`. Keep the implementation
literal and auditable. Do not import Pydantic or call a provider. Use the same
canonical JSON separators, key sorting, enum strings, weights, thresholds, issue
codes, transitions, and filenames as the full runner.

- [ ] **Step 5: Run full/portable parity and existing runner regressions**

Run: `.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py -q`

Expected: PASS.

- [ ] **Step 6: Commit role-packet execution**

```bash
git add scripts/harvest_skill.py scripts/harvest_portable.py tests/scripts/test_harvest_skill.py tests/scripts/test_harvest_portable.py
git commit -m "feat: add portable evaluation role packets"
```

### Task 1B: Mirror the evidence-level matrix in the portable substrate

**Files:**
- Modify: `scripts/attorney_eval_portable.py`
- Modify: `tests/scripts/test_attorney_eval_portable.py`
- Modify: `tests/scripts/test_harvest_skill.py` only where command parity binds terminal artifacts

After Core Task 7, mirror the persisted `1.2` contract and exact deterministic
matrix construction in the standard-library substrate. Full and portable runs
must produce byte-identical `evaluation-result.json` and
`evaluation-report.md`, including one row per ledger entry and all Markdown
escaping. Add differential vectors for one- and two-report cases, findings,
missing report locations, multiple citations, hostile table characters,
invalid/inconclusive terminals, matrix tampering, and mixed `1.1`/`1.2`
artifacts. Keep the outer `JudgeResponse` envelope at `1.0`.

Use TDD; run the focused portable suite, both runner suites, the full evaluation
suite, isolated standard-library import, Ruff, and mypy. Commit separately
before Task 2.

### Task 2: One-request host orchestration and public templates

**Files:**
- Create: `references/attorney-evaluation.md`
- Create: `assets/attorney-evaluation-case.template.json`
- Create: `assets/attorney-evaluation-response.template.json`
- Modify: `SKILL.md`
- Modify: `tests/skill/test_skill_package.py`

**Interfaces:**
- Consumes: the five runner commands from Task 1.
- Produces: a host-neutral loop that executes all judge operations automatically.

- [ ] **Step 1: Write failing skill-content tests**

```python
def test_skill_documents_one_request_fully_automated_evaluation() -> None:
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "Evaluate the latest Regulatory Harvest build against the locked suite." in skill
    assert "Do not ask the user to rate either report" in skill
    assert "references/attorney-evaluation.md" in skill


def test_evaluation_reference_seals_ledger_before_report_grading() -> None:
    reference = (ROOT / "references" / "attorney-evaluation.md").read_text()
    assert reference.index("Seal the legal ledger") < reference.index("Grade Report A")
    assert "CASE_INVALID" in reference
    assert "INCONCLUSIVE" in reference
```

- [ ] **Step 2: Run skill tests and verify red**

Run: `.venv/bin/pytest tests/skill/test_skill_package.py -q`

Expected: FAIL because the evaluation journey and reference are absent.

- [ ] **Step 3: Add the evaluation route to `SKILL.md`**

Insert an attorney-first route near the opening workflow:

```markdown
If the user asks to evaluate a report, compare a build, run the locked suite, or
assess whether Regulatory Harvest improved, read
`references/attorney-evaluation.md` and complete that workflow. Do not ask the
user to rate either report. Return the automated disposition and the path to the
requirement matrix.
```

Keep normal regulatory research as the default when the user asks a substantive
legal question rather than an evaluation question.

- [ ] **Step 4: Write the host-neutral automatic loop**

The reference must instruct the host to:

1. run `eval-init`;
2. read only `next-request.json`;
3. execute the named role using the embedded system instructions and schema;
4. start a fresh isolated context for each grader when the host supports it;
5. write only the strict response envelope;
6. run `eval-submit`;
7. repeat until the runner returns `completed`, `CASE_INVALID`, or
   `INCONCLUSIVE`;
8. run `eval-verify`; and
9. deliver the concise result without internal packet narration.

Explicitly prohibit reading the sealed mapping, other report, prior grader
response, or later-phase artifacts when a role packet does not contain them.
State that sequential same-context execution must record that isolation mode.

- [ ] **Step 5: Add copyable public-safe templates**

The case template must contain one clearly labeled synthetic current-law
example with explicit authority requests, source completeness, language, and
two candidate paths. Do not include placeholder content hashes: the runner
derives and binds hashes from the exact source and report bytes. The response
template must show the outer envelope only:

```json
{
  "schema_version": "1.0",
  "operation": "grade_report",
  "request_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "provider_name": "host-agent",
  "model_name": "host-configured-model",
  "judge_isolation": "fresh_context",
  "payload": {}
}
```

- [ ] **Step 6: Run skill tests and Markdown checks**

Run: `.venv/bin/pytest tests/skill/test_skill_package.py -q`

Expected: PASS.

Run: `.venv/bin/ruff check --no-cache scripts/harvest_skill.py scripts/harvest_portable.py`

Expected: PASS.

- [ ] **Step 7: Commit the universal orchestration**

```bash
git add SKILL.md references/attorney-evaluation.md assets/attorney-evaluation-case.template.json assets/attorney-evaluation-response.template.json tests/skill/test_skill_package.py
git commit -m "docs: add automated evaluation skill journey"
```

### Task 3: Package allowlist, extracted-ZIP verification, and privacy gates

**Files:**
- Modify: `scripts/skill-package-files.txt`
- Modify: `scripts/audit_release.py`
- Modify: `tests/scripts/test_build_skill.py`
- Modify: `tests/scripts/test_audit_release.py`
- Modify: `README.md`
- Modify: `docs/release-checklist.md`

**Interfaces:**
- Consumes: all public core and skill artifacts.
- Produces: one reproducible skill ZIP containing the evaluator and passing the clean-room audit.

- [ ] **Step 1: Write failing package and private-marker tests**

```python
def test_extracted_skill_completes_automated_evaluation_without_project_imports(tmp_path: Path) -> None:
    skill = build_and_extract_skill(tmp_path)
    result = run_scripted_evaluation_with_python_isolated(skill, tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "run" / "evaluation-result.json").is_file()
    assert (tmp_path / "run" / "evaluation-report.md").is_file()


def test_release_audit_rejects_private_evaluation_markers(tmp_path: Path) -> None:
    staged = copy_release_tree(tmp_path)
    (staged / "assets" / "attorney-evaluation-case.template.json").write_text(
        '{"private_round":"synthetic-private-round-marker"}',
        encoding="utf-8",
    )
    result = audit_tree(staged)
    assert "PRIVATE_EVALUATION_MARKER" in result.issue_codes
```

- [ ] **Step 2: Run package and release-audit tests and verify red**

Run: `.venv/bin/pytest tests/scripts/test_build_skill.py tests/scripts/test_audit_release.py -q`

Expected: FAIL because new files are not allowlisted and evaluation privacy checks are absent.

- [ ] **Step 3: Update the package allowlist and release audit**

Add the two templates, evaluation reference, and every new public core module to
`scripts/skill-package-files.txt` in sorted order. Extend release scanning across
the new evaluation reference, templates, Python modules, and built ZIP. Reject:

- absolute private-workshop paths;
- private workspace-root markers;
- known round directory names;
- report-to-system mappings or sealed-answer fields;
- retained private record identifiers and hashes; and
- private report phrases recorded only in the audit configuration.

Keep the actual private marker list in the local release-audit invocation or
test-owned synthetic values, not as public corpus content.

- [ ] **Step 4: Update attorney-first documentation**

Add one copyable prompt to `README.md`:

> Evaluate these two anonymous regulatory reports against the supplied authority
> and give me the automatic result.

Explain that normal users do not operate the internal judges. Keep installation
instructions host-specific, numbered, and consistent with one universal ZIP.
Add evaluator mutation, privacy, extracted-package, and full/portable parity
checks to `docs/release-checklist.md`.

- [ ] **Step 5: Build twice and verify byte-identical archives**

Run:

```bash
.venv/bin/python scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
.venv/bin/python scripts/build_skill.py --output dist/regulatory-harvest-skill.repeat.zip
shasum -a 256 dist/regulatory-harvest-skill.zip dist/regulatory-harvest-skill.repeat.zip
```

Expected: the two hashes are identical.

- [ ] **Step 6: Run extracted-ZIP, release, and full public gates**

Run: `.venv/bin/pytest tests/scripts/test_build_skill.py tests/scripts/test_audit_release.py tests/skill/test_skill_package.py -q`

Expected: PASS.

Run: `.venv/bin/python scripts/audit_release.py --root . --json`

Expected: JSON reports `valid: true`.

Run: `.venv/bin/pytest -q`

Expected: all tests pass except any documented intentional skip.

Run: `.venv/bin/ruff check --no-cache .`

Expected: PASS.

Run: `.venv/bin/mypy src/regulatory_harvest`

Expected: PASS.

- [ ] **Step 7: Commit the packaged evaluator**

```bash
git add scripts/skill-package-files.txt scripts/audit_release.py tests/scripts/test_build_skill.py tests/scripts/test_audit_release.py README.md docs/release-checklist.md
git commit -m "feat: package automated attorney evaluation"
```

## Skill-plan completion gate

- A user can request an evaluation once and never receives a rating prompt.
- The host follows strict role packets through a terminal automated disposition.
- Source-only operations contain no report text; graders are blind to identity and
  each other; the referee sees only material disputes.
- Full and portable deterministic artifacts match exactly.
- The extracted skill completes a synthetic evaluation under Python isolated
  mode without importing the checkout.
- The ZIP is reproducible and contains no private evaluation material.
- Existing research-mode examples, installation instructions, and complete-flow
  tests remain green.
