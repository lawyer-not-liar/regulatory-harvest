# Changelog

All notable changes to Regulatory Harvest will be recorded here. The project follows semantic versioning after the first public release.

## [Unreleased]

- Added one self-contained Agent Skill package for Codex and Claude Desktop, with supplied-source and current-web research modes.
- Added a host-agent draft bridge that resolves exact quotations and runs the existing COMBINE validation and export stages without a second model API.
- Added an attorney-facing matter runner, strict research charter and analysis-draft templates, currentness and authority guidance, and a reproducible universal ZIP builder.
- Added source publisher, effective-date, supersession metadata, and agent-proposed research gaps to the portable evidence bundle workflow.
- Added canonical source URLs, source-language metadata, predictable legal-issue categories, and concise authority links to attorney briefings.
- Added a strict adaptive brief schema for summary-first, matter-specific sections, paragraphs, lists, subsections, and tables, with deterministic finding-support and coverage checks.
- Added regulation-centered direct legal voice, a supported regulatory-walk recipe, and deterministic full and portable validation that keeps source-packet framing out of legal-analysis leads while preserving explicit limitations.
- Added the `regulatory-walk-v1` profile with required Key Requirements, Penalties and Enforcement, and Implementation Workplan anchors, category-placement checks, and explicit not-established states.
- Required named regulation headings for new profiled reports and separated provision-centered legal requirements from operational implementation advice.
- Added a full-corpus provision-lead inventory and a separate recall safety-net that caps blocking review work at three diverse priority leads per topic while retaining all leads for model-led completeness analysis.
- Added fully automated, source-readiness-gated attorney-report evaluation with sealed legal ledgers, independent grading, requirement-by-requirement matrices, exact generation capsules for formal build comparisons, and no human rating step.
- Separated evidence precision from provision recall in validation receipts and added a deterministic `coverage-review.json` audit artifact.
- Reframed currentness as an explicit verification boundary that lists the retained cited primary authorities without inferring chronology from retrieval order, instead of implying that an unverified authority is ineffective.
- Separated the readable `report.md` from `audit.md`, which retains exact quotations, full provenance, gap codes, validation details, review items, and run metadata.
- Added optional matter-title, source-role, and presentation-role metadata while preserving compatibility with older bundles and drafts that omit those fields.
- Limited Principal authorities to cited, successfully retained primary sources and removed duplicate full-question prose from the Executive summary.
- Added conservative primary-source inference for supported legal instruments on legislation.gov.uk, EUR-Lex, and Fedlex while keeping currentness independent.
- Added a web-mode primary-authority completion gate plus warnings for missing or unverified provenance metadata.
- Added two-pass discovery and verification, status-first analysis, applicability-assumption, non-English authority, and insufficient-evidence rules to the universal skill.
- Made the full Python provider path load the same versioned status-first, issue-category, translation, and attorney-briefing prompt contract.
- Expanded the clean-room audit to scan untracked, non-ignored candidate files before commit.
- Added a standard-library deterministic runner so installed skills can prepare, resolve exact citations, validate, report, and seal text or HTML matters without PyPI or preinstalled third-party libraries.
- Publication authorization, the public remote, and release date remain pending.

## [0.1.0] - Unreleased

### Added

- Versioned, SHA-256-sealed portable regulatory research bundles with mandatory attorney-review boundaries.
- Resumable COMBINE pipeline and atomic filesystem checkpoints.
- Local file and bounded public URL source intake, normalization, hashing, and provenance.
- Deterministic citation, support, coverage, and bundle validation.
- Offline CLI and Python API with optional OpenAI and Tavily providers.
- Optional cite/OpenContracts import and retryable export adapter.
- Optional LegalBench-RAG exact-character evaluator for user-supplied datasets.
- Synthetic fixtures, clean-room guidance, CI, and installation verification.

### Verified

- The local 0.1.0 candidate passed the warning-free test suite on Python 3.11 through 3.14, strict type checking, linting, clean-room audit, source and wheel builds, and a wheel-only offline acceptance run.
- Public repository creation and package publication remain blocked on the separate manual ownership and authorization gate.

[Unreleased]: CHANGELOG.md
[0.1.0]: CHANGELOG.md
