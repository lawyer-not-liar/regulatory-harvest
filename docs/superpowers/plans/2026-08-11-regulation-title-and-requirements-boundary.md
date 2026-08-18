# Regulation Title and Requirements Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every newly profiled Regulatory Harvest report use the regulation's name as its title and present source-supported legal requirements separately from operational implementation advice.

**Architecture:** Keep substantive drafting model-led and use the existing brief block purposes as the enforceable semantic boundary. Require `matter_title` at the new skill-charter boundary and on every `regulatory-walk-v1` bundle, validate canonical-section purposes in both the full and dependency-free engines, then teach the host to compose Key Requirements from source-supported claims and Implementation Workplan from practical implications and analysis.

**Tech Stack:** Python 3.11+, Pydantic 2, standard-library portable runner, pytest, Ruff, mypy, Markdown skill instructions, JSON templates, and the private localhost evaluation harness.

## Global Constraints

- Preserve schema version `1.0` and keep `ResearchRequest.matter_title` optional so older terminal bundles remain loadable.
- Require a nonblank matter title for every new skill charter and every `regulatory-walk-v1` brief.
- Render the matter title itself as the report H1. Do not prefix it with a generic attorney-briefing label.
- Allow only `legal_analysis` and `limitation` blocks in Key Requirements.
- Allow only `application`, `client_fact`, and `limitation` blocks in Implementation Workplan.
- Compose Key Requirements from `source_supported` claims, using accurate legal paraphrases and concise source markers. Keep exact quotations in `audit.md`.
- Compose Implementation Workplan from practical implications, analysis, client facts, assumptions, and gaps.
- Do not add deterministic verb matching or a rigid obligation-record schema.
- Preserve the current Executive Summary, narrative, Penalties and Enforcement, gap, currentness, evidence, and attorney-review behavior.
- Match issue code, level, path, message, related identifiers, and order between the full and portable validators.
- Preserve all unrelated dirty-worktree changes and stage only the files named by each commit step.
- Keep private evaluator material outside the public worktree. Do not modify any completed review round.
- Do not push, merge, publish, create a pull request, contact an external service, or access Epic systems.
- Retain this exact warning: `Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.`

---

### Task 1: Require named matters in new skill runs and profiled bundles

**Files:**
- Modify: `scripts/harvest_skill.py`
- Modify: `src/regulatory_harvest/validation/bundle.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/validation/test_bundle.py`
- Modify: `tests/analysis/test_report.py`

**Interfaces:**
- Consumes: `ResearchCharter.matter_title`, `ResearchBundle.request.matter_title`, and `brief.structure_profile`.
- Produces: early `INVALID_CHARTER` handling for a missing or blank new title and the stable bundle issue `BRIEF_MATTER_TITLE_MISSING` at `request.matter_title`.
- Preserves: generic title fallback only for older unprofiled terminal bundles.

- [x] **Step 1: Write failing charter and profiled-bundle tests**

Add `"matter_title": "Synthetic Documentation Rule"` to the shared `_charter()`
fixture in `tests/scripts/test_harvest_skill.py`. Set
`matter_title="Example Regulation"` on the shared `_bundle()` fixture in
`tests/validation/test_bundle.py` so its existing valid profiled brief remains a
valid baseline. Tests for backward compatibility and the new error must then
override that field explicitly. Add this missing-title case:

```python
def test_prepare_requires_a_concrete_matter_title(tmp_path: Path) -> None:
    source = tmp_path / "rule.txt"
    source.write_text("Synthetic rule.\n", encoding="utf-8")
    payload = _charter(source.name)
    payload.pop("matter_title")
    charter = tmp_path / "research-charter.json"
    charter.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(
        "prepare",
        "--charter",
        str(charter),
        "--matter",
        str(tmp_path / "matter"),
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["code"] == "INVALID_CHARTER"
    assert "matter_title" in error["message"]
```

Add exact profiled and unprofiled compatibility assertions in `tests/validation/test_bundle.py`:

```python
def test_profiled_brief_requires_a_concrete_matter_title() -> None:
    bundle = _bundle()
    bundle.request.matter_title = None
    bundle.brief = _profiled_brief()

    assert _issues_for(bundle, "BRIEF_MATTER_TITLE_MISSING") == [
        {
            "level": "error",
            "code": "BRIEF_MATTER_TITLE_MISSING",
            "path": "request.matter_title",
            "message": "A profiled attorney brief requires a concrete matter title.",
            "related_ids": ["regulatory-walk-v1"],
        }
    ]


def test_unprofiled_bundle_retains_the_legacy_title_fallback() -> None:
    bundle = _bundle()
    bundle.request.matter_title = None
    bundle.brief = _brief()

    assert "BRIEF_MATTER_TITLE_MISSING" not in _codes(bundle)
```

Parametrize the profiled test over `None` and `"   "` so validation proves that
the title is nonblank, not merely present. The existing `ResearchRequest` model
already rejects whitespace when parsing ordinary bundles; direct assignment in
this regression exercises the terminal validator itself.

In `tests/analysis/test_report.py`, assert that a named report starts with
`# Example Regulation`, its audit starts with
`# Example Regulation: Evidence and Validation Audit`, and an unprofiled bundle
without `matter_title` still starts with `# Attorney research briefing`.

- [x] **Step 2: Run the focused tests and verify the red state**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/validation/test_bundle.py tests/analysis/test_report.py -q
```

Expected: the missing-title charter is accepted and the profiled bundle lacks
`BRIEF_MATTER_TITLE_MISSING`.

- [x] **Step 3: Implement the full-engine title boundary**

Change the new skill charter field to a required string and validate it before
any matter files are staged:

```python
class ResearchCharter(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    matter_id: str
    matter_title: str

    @field_validator("matter_title")
    @classmethod
    def validate_matter_title(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()
```

At the beginning of `_profiled_brief_issues()` after the profile guard, append:

```python
if (
    bundle.request.matter_title is None
    or not bundle.request.matter_title.strip()
):
    issues.append(
        _issue(
            IssueLevel.ERROR,
            "BRIEF_MATTER_TITLE_MISSING",
            "request.matter_title",
            "A profiled attorney brief requires a concrete matter title.",
            BriefStructureProfile.REGULATORY_WALK_V1.value,
        )
    )
```

Keep the existing renderer fallback unchanged for old unprofiled bundles.

- [x] **Step 4: Run the focused tests and confirm green**

Run the Task 1 focused command and require every selected test to pass.

- [x] **Step 5: Commit only the Task 1 files**

```bash
git add scripts/harvest_skill.py src/regulatory_harvest/validation/bundle.py tests/scripts/test_harvest_skill.py tests/validation/test_bundle.py tests/analysis/test_report.py
git diff --cached --name-only
git commit -m "fix: require named regulations in new reports"
```

Before committing, confirm the staged list contains exactly those five paths.

---

### Task 2: Enforce the Key Requirements and Implementation purpose boundary

**Files:**
- Modify: `src/regulatory_harvest/validation/bundle.py`
- Modify: `tests/validation/test_bundle.py`

**Interfaces:**
- Consumes: canonical section roles and every direct or subsection `BriefBlock.purpose`.
- Produces: `BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID` and `BRIEF_IMPLEMENTATION_PURPOSE_INVALID`, each attached to the invalid block's `.purpose` path.
- Preserves: all valid block kinds, `limitation` in either section, and the existing Penalties and Enforcement contract.

- [x] **Step 1: Write exact failing tests for direct and nested blocks**

Add a parametrized test showing that both `application` and `client_fact` are
rejected in Key Requirements:

```python
@pytest.mark.parametrize(
    "purpose",
    [BriefBlockPurpose.APPLICATION, BriefBlockPurpose.CLIENT_FACT],
)
def test_key_requirements_rejects_nonlegal_block_purposes(
    purpose: BriefBlockPurpose,
) -> None:
    bundle = _bundle()
    bundle.request.matter_title = "Example Regulation"
    bundle.brief = _profiled_brief()
    bundle.brief.sections[0].blocks.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=purpose,
            text="Create the compliance workstream.",
        )
    )

    issues = _issues_for(bundle, "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID")

    assert issues == [
        {
            "level": "error",
            "code": "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
            "path": "brief.sections[0].blocks[1].purpose",
            "message": (
                "Key Requirements may contain only legal-analysis or limitation blocks."
            ),
            "related_ids": ["key_requirements"],
        }
    ]
```

Add a subsection regression by appending a `BriefSubsection` with one
`application` paragraph and assert the path is
`brief.sections[0].subsections[0].blocks[0].purpose`.

Add an Implementation Workplan regression:

```python
def test_implementation_workplan_rejects_legal_analysis_blocks() -> None:
    bundle = _bundle()
    bundle.request.matter_title = "Example Regulation"
    bundle.brief = _profiled_brief()
    bundle.brief.sections[2].blocks.append(
        BriefBlock(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            text="The rule requires documentation.",
            finding_ids=["finding-1"],
        )
    )

    assert _issues_for(bundle, "BRIEF_IMPLEMENTATION_PURPOSE_INVALID") == [
        {
            "level": "error",
            "code": "BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
            "path": "brief.sections[2].blocks[1].purpose",
            "message": (
                "Implementation Workplan may contain only application, client-fact, "
                "or limitation blocks."
            ),
            "related_ids": ["implementation"],
        }
    ]
```

- [x] **Step 2: Run the purpose tests and verify the red state**

```bash
.venv/bin/pytest tests/validation/test_bundle.py -q
```

Expected: all new purpose-boundary assertions fail because the current structural
validator accepts cross-purpose blocks.

- [x] **Step 3: Implement recursive purpose validation**

Inside `_profiled_brief_issues()`, after resolving the canonical section indexes,
scan direct and subsection blocks once per relevant role:

```python
purpose_contracts = (
    (
        BriefSectionRole.KEY_REQUIREMENTS,
        {BriefBlockPurpose.LEGAL_ANALYSIS, BriefBlockPurpose.LIMITATION},
        "BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
        "Key Requirements may contain only legal-analysis or limitation blocks.",
    ),
    (
        BriefSectionRole.IMPLEMENTATION,
        {
            BriefBlockPurpose.APPLICATION,
            BriefBlockPurpose.CLIENT_FACT,
            BriefBlockPurpose.LIMITATION,
        },
        "BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
        (
            "Implementation Workplan may contain only application, client-fact, "
            "or limitation blocks."
        ),
    ),
)
for role, allowed, code, message in purpose_contracts:
    if role not in canonical_index_by_role:
        continue
    section_index = canonical_index_by_role[role]
    section = brief.sections[section_index]
    blocks = [
        (f"brief.sections[{section_index}].blocks[{index}]", block)
        for index, block in enumerate(section.blocks)
    ]
    for subsection_index, subsection in enumerate(section.subsections):
        blocks.extend(
            (
                f"brief.sections[{section_index}].subsections[{subsection_index}]"
                f".blocks[{block_index}]",
                block,
            )
            for block_index, block in enumerate(subsection.blocks)
        )
    for block_path, block in blocks:
        if block.purpose not in allowed:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    code,
                    f"{block_path}.purpose",
                    message,
                    role.value,
                )
            )
```

Keep this structural check content-neutral. Do not inspect verbs or attempt to
infer legal meaning from block text.

- [x] **Step 4: Run the focused validation tests and confirm green**

Run the Task 2 test command and require all selected tests to pass.

- [x] **Step 5: Commit only the Task 2 files**

```bash
git add src/regulatory_harvest/validation/bundle.py tests/validation/test_bundle.py
git diff --cached --name-only
git commit -m "fix: separate legal requirements from implementation"
```

Confirm only those two paths are staged.

---

### Task 3: Match the dependency-free portable runtime

**Files:**
- Modify: `scripts/harvest_portable.py`
- Modify: `tests/scripts/test_harvest_portable.py`
- Modify: `tests/analysis/test_report_parity.py`

**Interfaces:**
- Consumes: the Task 1 title contract and Task 2 full-engine issue payloads.
- Produces: identical title and purpose validation in the portable runner.
- Preserves: standard-library-only execution and rendering compatibility for old unprofiled bundles.

- [x] **Step 1: Write failing portable charter and parity scenarios**

Add `matter_title` to the portable `_charter()` fixture. Add one test that removes
the field and one that sets it to whitespace; both must expect
`PortableInputError` with `charter.matter_title`.

Extend `_STRUCTURAL_CODES` in `tests/analysis/test_report_parity.py` with:

```python
"BRIEF_MATTER_TITLE_MISSING",
"BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID",
"BRIEF_IMPLEMENTATION_PURPOSE_INVALID",
```

Extend `_apply_structural_failure()` with three exact mutations:

```python
elif scenario == "matter-title":
    bundle.request.matter_title = None
elif scenario == "blank-matter-title":
    bundle.request.matter_title = "   "
elif scenario == "requirements-purpose":
    brief.sections[0].blocks[0].purpose = BriefBlockPurpose.APPLICATION
elif scenario == "implementation-purpose":
    brief.sections[2].blocks[0].purpose = BriefBlockPurpose.LEGAL_ANALYSIS
```

Add the four scenario names to
`test_portable_and_full_structural_validation_match` and add a nested-subsection
parity test for the Key Requirements path.

- [x] **Step 2: Run portable and parity tests and verify the red state**

```bash
.venv/bin/pytest tests/scripts/test_harvest_portable.py tests/analysis/test_report_parity.py -q
```

Expected: the portable charter still accepts a missing title and its structural
issues differ from the full engine.

- [x] **Step 3: Implement the portable title and purpose contracts**

In `_charter()`, move `matter_title` from the optional key set to the required key
set and parse it with:

```python
"matter_title": _nonblank(charter["matter_title"], "charter.matter_title"),
```

In portable `_profiled_brief_issues()`, treat an absent or whitespace-only title
as missing and mirror the full-engine issue exactly. Mirror the two
purpose-contract loops using string values and the existing normalized portable
section dictionaries. Emit the same paths, messages, related identifiers, and
order as the full engine.

- [x] **Step 4: Run portable, parity, and full structural tests**

```bash
.venv/bin/pytest tests/scripts/test_harvest_portable.py tests/analysis/test_report_parity.py tests/validation/test_bundle.py -q
```

Require all selected tests to pass.

- [x] **Step 5: Commit only the Task 3 files**

```bash
git add scripts/harvest_portable.py tests/scripts/test_harvest_portable.py tests/analysis/test_report_parity.py
git diff --cached --name-only
git commit -m "fix: match report boundaries in portable runtime"
```

Confirm only those three paths are staged.

---

### Task 4: Correct the authoring recipe, examples, and end-to-end behavior

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `references/draft-schema.md`
- Modify: `assets/analysis-draft.template.json`
- Modify: `src/regulatory_harvest/analysis/prompts/build-v1.md`
- Modify: `tests/combine/test_stages.py`
- Modify: `tests/skill/test_skill_package.py`
- Modify: `tests/scripts/test_harvest_skill.py`
- Modify: `tests/e2e/test_skill_flow.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the validated title and purpose contracts from Tasks 1 through 3.
- Produces: one positive host-authoring recipe that copies legal meaning from source-supported claims into Key Requirements and sends practical implications to Implementation Workplan.
- Preserves: exact quotation isolation in `audit.md`, adaptive noncanonical headings, and the existing penalties treatment.

- [x] **Step 1: Write failing prompt, package, template, and end-to-end tests**

Extend `test_skill_requires_profiled_key_requirements_and_penalties_sections()`
so each of `SKILL.md`, `references/draft-schema.md`, and `build-v1.md` contains the
positive recipe. Extend
`test_model_requests_use_the_versioned_attorney_briefing_prompts()` with the same
assertions against the build prompt. Use these stable semantic needles:

```python
for term in (
    "source_supported",
    "practical_implication",
    "provision-centered",
    "regulated actor or rights holder",
    "exact quotations",
    "audit.md",
):
    assert term in document.casefold()
```

In the skill-package test, run that loop once for each document. In the prompt
test, bind `document = build_request.system_instructions`. This makes omissions on
any individual authoring surface fail rather than allowing one document to mask
another.

In `test_skill_runtime_resources_are_complete_and_templates_are_valid_json()`,
recursively collect block purposes and assert Key Requirements contains only
`legal_analysis` or `limitation`, while Implementation Workplan contains only
`application`, `client_fact`, or `limitation`.

Update the end-to-end fixture to include:

```python
"matter_title": "Synthetic Documentation Rule",
```

Change its Key Requirements block to `legal_analysis` with the paraphrase
`Covered controllers must document material deployment risks.` Keep the existing
Implementation Workplan action. Assert:

```python
assert report.startswith("# Synthetic Documentation Rule\n")
assert "Covered controllers must document material deployment risks." in report
assert report.count("Create the risk record before deployment.") == 1
assert audit.startswith(
    "# Synthetic Documentation Rule: Evidence and Validation Audit\n"
)
assert RULE_TEXT not in report
assert RULE_TEXT in audit
```

Update `_draft()` in `tests/scripts/test_harvest_skill.py` so its Key Requirements
unit is a direct `legal_analysis` paraphrase rather than an `application` action.

- [x] **Step 2: Run the authoring-contract tests and verify the red state**

```bash
.venv/bin/pytest tests/combine/test_stages.py tests/skill/test_skill_package.py tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py -q
```

Expected: the positive source-to-section recipe is absent, the schema example
still places implementation inside Key Requirements, and the end-to-end fixture
does not satisfy the new title and purpose contract.

- [x] **Step 3: Rewrite the positive recipe and public-safe examples**

In `SKILL.md`, `references/draft-schema.md`, and `build-v1.md`, require this
authoring sequence:

1. Enumerate every material `source_supported` claim belonging to a requirements finding.
2. Paraphrase each as a direct legal rule naming the regulated actor or rights holder, duty or right, trigger or threshold, timing, and qualification when material.
3. Attach the supporting `finding_ids` and only then group rules under provision-centered headings.
4. Do not derive Key Requirements from `practical_implication` or analysis claims.
5. Convert those practical implications and analysis claims into the separate Implementation Workplan.

Replace the `Implementation Sequence` subsection currently nested under Key
Requirements in `references/draft-schema.md` with a legal-topic example whose
blocks use `legal_analysis`. Keep exact quotations solely in the evidence-layer
example and audit explanation.

Ensure `assets/analysis-draft.template.json` demonstrates only the permitted
purposes. Update the README's deliverables description so attorneys understand
that the H1 names the regulation, Key Requirements states the law, and
Implementation Workplan contains recommended action.

- [x] **Step 4: Record the public-safe change**

Add a concise changelog entry describing named report titles and the stricter
requirements-versus-implementation presentation boundary. Do not mention private
matters, sources, ratings, or report text.

- [x] **Step 5: Run the authoring and end-to-end tests and confirm green**

Run the Task 4 focused command and require all selected tests to pass.

- [x] **Step 6: Commit only the Task 4 files**

```bash
git add SKILL.md README.md references/draft-schema.md assets/analysis-draft.template.json src/regulatory_harvest/analysis/prompts/build-v1.md tests/combine/test_stages.py tests/skill/test_skill_package.py tests/scripts/test_harvest_skill.py tests/e2e/test_skill_flow.py CHANGELOG.md
git diff --cached --name-only
git commit -m "docs: teach provision-centered requirements"
```

Confirm the staged set contains only the ten named paths.

---

### Task 5: Propagate regulation titles in future private evaluation rounds

**Files:**
- Modify: `$PRIVATE_EVALUATOR_ROOT/tools/pilot.py`
- Modify: `$PRIVATE_EVALUATOR_ROOT/tests/test_pilot.py`

**Interfaces:**
- Consumes: `CaseState.regulation_name` already derived from the preserved record.
- Produces: `research-charter.json` with `matter_title` set to that exact regulation name.
- Preserves: all completed rounds and their immutable generated reports.

- [x] **Step 1: Write the failing evaluator test**

In `test_materialize_source_rich_case_uses_only_local_input_locations()`, add:

```python
self.assertEqual(charter["matter_title"], "Example Rule")
```

- [x] **Step 2: Run the focused evaluator test and verify the red state**

```bash
python3 -m unittest tests.test_pilot.PilotMaterializationTests.test_materialize_source_rich_case_uses_only_local_input_locations -v
```

Expected: `matter_title` is absent.

- [x] **Step 3: Add the title to newly materialized charters**

In `build_charter()`, add this field beside `matter_id`:

```python
"matter_title": state.regulation_name,
```

Do not edit any charter already sealed inside a completed round.

- [x] **Step 4: Run focused and complete evaluator tests**

```bash
python3 -m unittest tests.test_pilot.PilotMaterializationTests.test_materialize_source_rich_case_uses_only_local_input_locations -v
python3 -m unittest discover -s tests -v
```

Require all evaluator tests to pass.

- [x] **Step 5: Verify private preservation boundaries**

Recompute the recorded aggregate SHA-256 hashes for the root reviewer and every
completed round. Require all pre-change paths to match their baselines and run:

```bash
python3 "$OFFLINE_GUARD"
```

This private evaluator is not a Git repository. Record the change and validation
in its existing `.sdd` state rather than creating a public commit.

---

### Task 6: Verify, package, install, and run the next private comparison

**Files:**
- Add: `docs/verification/2026-08-11-regulation-title-and-requirements-boundary.md`
- Rebuild: `dist/regulatory-harvest-skill.zip`
- Replace: `$INSTALLED_SKILL_ROOT/regulatory-harvest/` through a staged, verified local installation with rollback retained until validation passes.
- Create: `$PRIVATE_EVALUATOR_ROOT/rounds/$PRIVATE_EVALUATION_ROUND/`
- Add: private round state and progress files under `$PRIVATE_EVALUATOR_ROOT/.sdd/`.

**Interfaces:**
- Consumes: the completed public implementation, private preserved exports, every prior selection audit, and the existing localhost reviewer.
- Produces: one reproducible universal ZIP, a byte-identical local installation, public-safe verification evidence, and a fresh resumable three-case private blind comparison.
- Preserves: all publication, confidentiality, and manual release gates.

- [x] **Step 1: Run the focused and complete public quality suites**

```bash
.venv/bin/pytest tests/scripts/test_harvest_skill.py tests/validation/test_bundle.py tests/analysis/test_report.py tests/scripts/test_harvest_portable.py tests/analysis/test_report_parity.py tests/combine/test_stages.py tests/skill/test_skill_package.py tests/e2e/test_skill_flow.py -q
.venv/bin/pytest -q -rs
.venv/bin/ruff check .
.venv/bin/mypy src
python3 scripts/audit_release.py --json
git diff --check
```

Record exact counts and any intentional skips. Do not call a skipped live-service
test completed local coverage.

- [x] **Step 2: Perform the sequential adversarial review**

Inspect title backward compatibility, blank-title handling, direct and nested
purpose paths, duplicate validation issues, full/portable sort order, absence
states, exact-quotation isolation, and false-positive risk. Because delegation is
not authorized, perform implementer, reviewer, adversarial, and evaluator passes
sequentially and record that limitation.

If a Critical or Important finding appears, write a failing regression test,
repair only the implicated behavior, and rerun every affected suite. Stop after
three failed attempts on the same approach.

- [x] **Step 3: Build and validate the universal package twice**

```bash
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
rh_build_check="$(mktemp -d /tmp/rh-boundary-build.XXXXXX)"
python3 scripts/build_skill.py --output "$rh_build_check/regulatory-harvest-skill.zip"
cmp dist/regulatory-harvest-skill.zip "$rh_build_check/regulatory-harvest-skill.zip"
unzip -t dist/regulatory-harvest-skill.zip
unzip -q dist/regulatory-harvest-skill.zip -d "$rh_build_check/extracted"
python3 "$SKILL_VALIDATOR" "$rh_build_check/extracted/regulatory-harvest"
python3 scripts/audit_release.py --repo "$rh_build_check/extracted/regulatory-harvest" --json
```

Require byte-identical archives, one `regulatory-harvest/` archive root, no private
evaluation identifiers, and no tests, caches, Git state, or internal plans in the
ZIP.

- [x] **Step 4: Install with rollback and smoke-test the installed skill**

Move the current installed directory to a temporary rollback directory, copy the
verified extracted `regulatory-harvest/` directory into
`$INSTALLED_SKILL_ROOT`, and compare the installed tree recursively with
the extracted tree. Do not alter any other installed skill.

Use a fresh temporary directory and public synthetic text to run the installed
dependency-free `prepare` and `finalize` commands with site packages and package
index access disabled. Require a named H1, a legal-rule Key Requirements section,
one operational Implementation Workplan, exact evidence only in the audit,
`valid: true`, `status: completed`, and zero blocking review items.

- [x] **Step 5: Materialize a fresh private depth round**

From the private evaluator root, record byte-level hashes for the root reviewer
and all completed rounds. Then run:

```bash
rh_prior_args=()
while IFS= read -r rh_audit; do
  rh_prior_args+=(--prior-selection-audit "$rh_audit")
done < <(find rounds -path '*/sealed/selection-audit.json' -type f | sort)
python3 tools/remediation_round.py materialize \
  --export "$PRIVATE_ANALYSIS_EXPORT" \
  --source-text-export "$PRIVATE_SOURCE_TEXT_EXPORT" \
  --regulation-fulltext-export "$PRIVATE_REGULATION_FULLTEXT_EXPORT" \
  --original-manifest cases.json \
  --prior-session blind-review \
  --redactions blind-review-redactions.json \
  --round "rounds/$PRIVATE_EVALUATION_ROUND" \
  --profile depth-validation \
  --target-minutes 45 \
  "${rh_prior_args[@]}"
```

Require one unseen smoke case, three unseen scored cases, full-preserved evidence,
source parity, no prior record reuse, no visible legacy reference, and explicit
client-fact parity metadata.

- [x] **Step 6: Generate through the smoke, evidence, and seal gates**

Use the installed skill in `provided-only` mode. Complete the unseen smoke case
first. Require both evidence-precision and provision-recall gates before drafting
the three scored cases.

For each scored case, build Key Requirements by enumerating source-supported
requirements claims before grouping them. Use provision-centered headings and
direct legal paraphrases. Put operational actions only in Implementation
Workplan. Require the named regulation as H1, terminal completion, both evidence
gates, zero blocking review items, exact evidence in the audit, and the mandated
attorney warning.

Keep every Legacy comparator sealed until all three Regulatory Harvest reports
are terminal. Then write only the three selected frozen comparators and
immediately seal the complete generation set before building the reviewer.

- [x] **Step 7: Build, verify, and launch the blind reviewer**

Reveal only the three frozen comparators selected for the completed scored cases,
seal generation, and build the round-local reviewer. Verify the round, reviewer,
JSON, JavaScript, table rendering, exact disclaimer, source parity, preservation
hashes, and offline guard. Start the reviewer on `127.0.0.1`, confirm zero progress,
and do not expose its fragment token or answer key.

- [x] **Step 8: Record verification evidence and stop at the release gate**

Write the exact commands, results, archive hashes, installed-tree comparison,
private preservation checks, reviewer status, remaining limitations, and skipped
external checks to
`docs/verification/2026-08-11-regulation-title-and-requirements-boundary.md`.

Commit only public implementation and verification files. Leave the branch local.
Do not push, merge, publish, create a pull request, or announce a release.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
