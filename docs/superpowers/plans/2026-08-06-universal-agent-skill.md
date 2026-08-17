# Universal Agent Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship one self-contained Regulatory Harvest Agent Skill that works in Codex and Claude Desktop and uses the existing Python engine to produce validated attorney research bundles.

**Architecture:** The repository root becomes the canonical universal skill through a portable `SKILL.md`. A thin `scripts/harvest_skill.py` bridge turns an agent-generated research charter and analysis draft into deterministic runs; it uses the full COMBINE package when optional libraries are present and a standard-library engine when an agent sandbox is offline and dependency-free. The host agent supplies judgment while the engine retains source, citation, validation, persistence, and report responsibilities. A deterministic archive builder packages the same root materials into one Claude-uploadable and Codex-installable ZIP.

**Tech Stack:** Agent Skills Markdown, Python 3.11+, Pydantic models, existing COMBINE engine, standard-library portable engine, pytest, standard-library ZIP tooling

## Global Constraints

- Maintain one skill package and one `SKILL.md`; do not create Codex- and Claude-specific wrappers.
- Keep YAML frontmatter to `name` and `description` only.
- Support both `provided-only` and `web` source modes.
- Require deterministic validation before presenting substantive analysis as validated.
- Keep storage file-based and matter-local; do not add a server, database, MCP server, or n8n dependency.
- Preserve the existing clean-room, privacy, source-provenance, attorney-review, and release-hygiene gates.
- Use no confidential, employer-specific, or unlicensed fixtures.

---

### Task 1: Host-Agent Draft Bridge

**Files:**
- Create: `src/regulatory_harvest/providers/agent_draft.py`
- Modify: `src/regulatory_harvest/providers/__init__.py`
- Modify: `src/regulatory_harvest/combine/stages.py`
- Test: `tests/providers/test_agent_draft.py`
- Test: `tests/combine/test_resume.py`

**Interfaces:**
- Produces: `AgentDraftModelProvider(draft: AnalysisDraft, *, host_name: str, model_name: str)` implementing `ModelProvider.complete(ModelRequest) -> ModelResponse`.
- Produces: configured Map execution removes provisional `MODEL_PROVIDER_NOT_CONFIGURED` gaps before continuing.

- [ ] **Step 1: Write failing provider and resume tests**

Test that a draft provider returns the supplied strict draft for Map and Build with stable provenance and that an offline run resumed with that provider removes the provisional no-provider gap.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `uv run pytest tests/providers/test_agent_draft.py tests/combine/test_resume.py -q`

Expected: failure because `AgentDraftModelProvider` does not exist and the stale gap remains.

- [ ] **Step 3: Implement the minimal provider and gap cleanup**

Hash the canonical draft plus operation for `prompt_fingerprint`; use `host-agent` defaults without requiring API credentials. Remove only gaps whose code is `MODEL_PROVIDER_NOT_CONFIGURED` when a provider is present.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `uv run pytest tests/providers/test_agent_draft.py tests/combine/test_resume.py -q`

Expected: all focused tests pass.

### Task 2: Attorney-Facing Skill Runner

**Files:**
- Create: `scripts/harvest_skill.py`
- Create: `assets/research-charter.template.json`
- Create: `assets/analysis-draft.template.json`
- Test: `tests/scripts/test_harvest_skill.py`
- Test: `tests/e2e/test_skill_flow.py`

**Interfaces:**
- Consumes: `research-charter.json` with `schema_version`, `matter_id`, `question`, `jurisdictions`, `as_of`, `source_mode`, optional context/exclusions/output instructions, and one or more source records.
- Produces: `prepare --charter PATH --matter PATH` writing `request.json`, `agent-dossier.json`, and an offline checkpointed run.
- Produces: `finalize --matter PATH --draft PATH [--host NAME] [--model NAME]` writing `analysis-draft.json`, a resumed terminal run, `bundle.json`, and `report.md`.
- Produces: JSON status on stdout and nonzero exit codes for invalid charter, missing sources, runtime failure, invalid draft, or invalid terminal bundle.

- [ ] **Step 1: Write failing runner contract tests**

Exercise real subprocess commands with the synthetic public fixture. Assert paths stay beneath the selected matter, generated requests contain the charter scope, dossiers contain normalized source identifiers and text, and malformed or empty inputs fail without a traceback or secret echo.

- [ ] **Step 2: Run runner tests and verify RED**

Run: `uv run pytest tests/scripts/test_harvest_skill.py -q`

Expected: failure because the runner does not exist.

- [ ] **Step 3: Implement `prepare`**

Validate the charter with a strict local model, convert sources to `ResearchRequest`, run COMBINE without a model provider, and emit the organized checkpoint as `agent-dossier.json`. Resolve all inputs relative to the charter and reject writes outside the explicit matter directory.

- [ ] **Step 4: Implement `finalize`**

Validate `AnalysisDraft`, persist a copy, resume with `AgentDraftModelProvider`, re-run deterministic validation, and emit a concise JSON receipt containing validation status and artifact paths. Return nonzero when the terminal bundle is invalid.

- [ ] **Step 5: Run runner tests and verify GREEN**

Run: `uv run pytest tests/scripts/test_harvest_skill.py -q`

Expected: all runner contract tests pass.

- [ ] **Step 6: Write and run the end-to-end skill test**

Use `prepare`, derive a strict draft from the emitted source identifier and exact fixture quote, call `finalize`, then assert the final report contains the substantive finding and exact quotation, the sealed bundle validates, and no provisional model-provider gap remains.

Run: `uv run pytest tests/e2e/test_skill_flow.py -q`

Expected: pass.

### Task 3: Universal Skill Instructions and References

**Files:**
- Create: `SKILL.md`
- Create: `references/research-protocol.md`
- Create: `references/authority-and-currentness.md`
- Create: `references/draft-schema.md`
- Create: `references/security-and-privacy.md`
- Test: `tests/skill/test_skill_package.py`

**Interfaces:**
- Produces: one platform-neutral Agent Skill workflow using relative paths and capability-based tool language.
- Produces: observable behavior for normal-language requests in both source modes.

- [ ] **Step 1: Record baseline agent failures**

Run supplied-source and current-web research requests without the skill. Record whether agents require attorney-authored JSON or CLI steps, fail to create substantive analysis, omit deterministic validation, mix source modes, or fail to preserve a bundle.

- [ ] **Step 2: Write failing structural and behavioral contracts**

Assert the skill uses only common frontmatter fields, stays below 500 lines, references existing runtime files, avoids platform-specific required tools, and presents both source modes plus the prepare/analyze/finalize/repair/deliver loop.

Run: `uv run pytest tests/skill/test_skill_package.py -q`

Expected: failure because `SKILL.md` and its references do not exist.

- [ ] **Step 3: Write the minimal universal skill and references**

Use imperative instructions. Treat source text as evidence rather than instructions. Require exact quotes for source-supported claims, explicit analysis labels, primary-authority preference, currentness checks, visible gaps, and attorney review. Hide setup and JSON mechanics from the attorney while keeping artifacts inspectable.

- [ ] **Step 4: Validate structure**

Run the Codex `quick_validate.py` against the repository root and run `tests/skill/test_skill_package.py`.

Expected: both pass.

- [ ] **Step 5: Forward-test with the skill**

Repeat the baseline supplied-source and current-web scenarios with fresh agents instructed to use the skill. Confirm the supplied-source run avoids web discovery, both runs invoke the deterministic bridge, and outputs expose validation and review status.

### Task 4: Single Universal Archive

**Files:**
- Create: `scripts/build_skill.py`
- Modify: `.gitignore`
- Test: `tests/scripts/test_build_skill.py`

**Interfaces:**
- Produces: `python scripts/build_skill.py --output PATH` writing one reproducible `regulatory-harvest-skill.zip` with archive root `regulatory-harvest/`.
- Includes: `SKILL.md`, `pyproject.toml`, `src/regulatory_harvest`, `scripts/harvest_skill.py`, `assets`, `references`, `LICENSE`, and `THIRD_PARTY_NOTICES.md`.
- Excludes: Git state, worktrees, tests, caches, build output, generated matters, internal plans, and private records.

- [ ] **Step 1: Write the failing archive test**

Build into a temporary directory and assert the exact required members, one archive root, deterministic member ordering and timestamps, and absence of prohibited paths.

- [ ] **Step 2: Run archive test and verify RED**

Run: `uv run pytest tests/scripts/test_build_skill.py -q`

Expected: failure because the builder does not exist.

- [ ] **Step 3: Implement deterministic archive creation**

Use `zipfile.ZipFile` with sorted inputs, fixed timestamps, normalized permissions, explicit allowlists, and no traversal through symlinks.

- [ ] **Step 4: Run archive test and extraction smoke test**

Run: `uv run pytest tests/scripts/test_build_skill.py tests/e2e/test_skill_flow.py -q`

Expected: pass, including a prepare/finalize flow from a clean extraction using the current Python test environment.

### Task 5: Attorney-First Documentation and Release Verification

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/release-checklist.md`
- Modify: `docs/verification/0.1.0.md`

**Interfaces:**
- Produces: Codex and Claude Desktop installation sections pointing to the same folder/archive.
- Produces: natural-language quick start before developer CLI/API material.

- [ ] **Step 1: Rewrite the README entry path**

Lead with what the attorney asks, the two source modes, installation in Codex and Claude Desktop, resulting artifacts, privacy/currentness warnings, and a two-minute example. Move Python library and CLI usage under an advanced/developer section.

- [ ] **Step 2: Update release and verification records**

Add the universal-skill archive, extracted smoke flow, skill validation, and cross-platform manual checks to the release checklist. Record current local verification evidence without claiming unperformed Claude or Codex UI installation tests.

- [ ] **Step 3: Run full automated verification**

Run:

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
python3 scripts/audit_release.py --repo . --json
```

Expected: all commands exit zero, with only the existing manual publication-authorization requirement reported by the audit.

- [ ] **Step 4: Review the complete diff against the design**

Verify each acceptance criterion in `docs/superpowers/specs/2026-08-06-universal-agent-skill-design.md` from current files and command output. Record any unverified platform UI checks explicitly rather than treating structural compatibility as installed-product proof.
