# Changelog

All notable changes to Regulatory Harvest will be recorded here. The project follows semantic versioning after the first public release.

## [Unreleased]

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
