# Changelog

All notable changes to Regulatory Harvest will be recorded here. The project follows semantic versioning after the first public release.

## [Unreleased]

## [0.1.0-beta.4] - 2026-08-23

- Added general materiality safeguards from merged PR #7 that treat
  `not_material` dispositions as provisional until responsive units, leads,
  and citation quotes are challenged against the atomic rule graph.
- Added graph-to-report omission safeguards that trace responsive source
  material through claims and material graph elements into rendered report
  prose without losing independently operative qualifications.
- The beta.3 post-release private run completed end to end. Both grader lanes
  independently reached `FAIL` on the locked recall and coverage floors. That
  result proves technical operability, not private content readiness. Beta.4
  has not yet earned a private `PASS`.
- No performance, benchmark, or report-quality claim is made. No PyPI
  distribution is published.
- Protocol 2.2 remains opt-in and experimental; Protocol 2.1 remains the
  default.

## [0.1.0-beta.3] - 2026-08-23

- Changed Protocol 2.2 grader reconciliation to score both lanes
  independently. A common `PASS` or `FAIL` is preserved when evidence details
  differ without changing the rubric outcome; outcome-changing disagreement
  remains `INCONCLUSIVE` with `GRADER_DISAGREEMENT`.
- Both raw grader aggregates remain sealed with their evidence choices so
  requirement-level and passage-level variance remains available for later
  calibration analysis.
- The beta.2 private end-to-end run completed every evaluator role and grading.
  Both lanes independently reached `FAIL`, but the prior exact-detail rule made
  the result `INCONCLUSIVE`; beta.3 corrects that outcome-stability defect.
- Public tests passed on Python 3.11 through 3.14.
- The beta.3 post-release private run completed end to end. Both grader lanes
  independently reached `FAIL` on the locked content floors. That result proves
  technical operability, not private content readiness. No performance,
  benchmark, or report-quality claim is made.
- Protocol 2.2 remains opt-in and experimental; Protocol 2.1 remains the
  default.

## [0.1.0-beta.2] - 2026-08-22

- Added the recoverable Protocol 2.2 attorney-report evaluator as an explicit
  option. Protocol 2.2 remains opt-in and experimental; Protocol 2.1 remains
  the new-run default.
- Passed the public test, type, lint, package, reproducibility, and privacy
  gates for the reviewed Protocol 2.2 candidate.
- A separately authorized private readiness evaluation verified package and
  input binding, live role execution, safe pause, and exact recovery, but
  evidence references could not be resolved before any role response was
  accepted or grading began. Private readiness is therefore incomplete.
- Made no performance, benchmark, report-quality, legal-correctness,
  completeness, currency, or applicability claim. Attorney validation remains
  required.
- After the reviewed candidate, hardened POSIX rollback ownership against
  immediate inode-number reuse and made development-only AST policy inventories
  stable across Python 3.11 through 3.14. This CI portability work does not
  loosen evidence binding or policy checks, and it gives the release ZIP a new
  archive hash.

## [0.1.0-beta.1] - 2026-08-17

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
- Prepared the first public experimental beta without a performance,
  benchmark, or report-quality claim.

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
- The GitHub prerelease packages the unchanged `0.1.0` engine. No PyPI
  distribution is published.

[Unreleased]: https://github.com/lawyer-not-liar/regulatory-harvest/compare/v0.1.0-beta.4...HEAD
[0.1.0-beta.4]: https://github.com/lawyer-not-liar/regulatory-harvest/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/lawyer-not-liar/regulatory-harvest/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/lawyer-not-liar/regulatory-harvest/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/lawyer-not-liar/regulatory-harvest/releases/tag/v0.1.0-beta.1
