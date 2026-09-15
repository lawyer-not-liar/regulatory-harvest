# Beta.10 prepublication verification

This is a prepublication engineering snapshot recorded on 2026-09-15. It is not
a release announcement, a legal-quality benchmark, or a claim that every host
acceptance check was complete at this snapshot. Consult the beta.10 release notes
and the CI run for the tagged commit for the final publication disposition.

## Candidate identity

The universal skill archive contains 148 files and 953,395 bytes, with SHA-256
`6c03079acfb664c828aeb0149d34692b4b78c6c06394d55bb3864b6e83352d1e`.
Repeated builds and the installed Codex copy matched these exact archive members.
The beta.9 tag and archive remain separate and unchanged.

## Automated checks

- Complete Python 3.13.6 / pytest 9.1.1 suite: **6,536 passed, 2 skipped, zero
  failures**, in 1:59:55. All 392 frozen candidate files matched their before/after
  hashes. The suite used its own locked environment, ordinary POSIX umask, and the
  platform's default temporary directory. No tests were excluded.
- One warning concerns a test's tar extraction default changing in Python 3.14.
  It is not a runtime failure or a warning-free result.
- Ruff passed. Mypy passed for 104 source files. Wheel and source distribution built.
- Repository and exact-archive clean-room audit: zero automated findings. The
  scanner's separate manual confirmation requirement is not an automated pass.
- The extracted skill passed the skill-creator quick validator. It also passed
  `skills-ref validate` using the official reference implementation at commit
  `69ef37e9424c0a7ea9dd2293b559e43ec8176379`, installed only in a detached validation
  environment, not added as a runtime dependency.
- A clean wheel installation outside the checkout loaded byte-identical readiness
  rubric resources and completed the offline CLI run, bundle validation, and report.
  Its synthetic local source produced three warning-level provenance diagnostics.
- The licensed one-case synthetic LegalBench-RAG-shaped calculation passed. This
  tests calculation plumbing, not real-world legal performance.

The first isolated suite invocation exposed three stale tests and environment
assumptions: a missing clone-local interpreter, a restrictive inherited umask, and
a forced temporary-directory alias. The stale tests were corrected to preserve
V3 unique-passage filtering and coherent legacy-downgrade rejection; production
acceptance checks were not loosened. The complete rerun above is the release
candidate's test result, not an aggregation of selected partial runs.

## Installed host checks

The actual installed Codex skill completed `prepare` and `finalize` in provided-only
mode using the public fictional rule fixture and in web mode using a transparently
selected exact National Archives Amendment XXVI excerpt. Both receipts reported
`completed`, `valid: true`, and true precision, proposition-coverage, and
provision-recall flags, with no coverage diagnostics. The reports retained their
synthetic/excerpt, currentness, remedy, and applicability limitations.

A separate web-mode test correctly refused to treat the fictional GitHub fixture
as official primary authority. That refusal is negative-test evidence, not a
successful web research result.

Claude **web** accepted and enabled the same 148-file archive. Its first autonomous
provided-only smoke attempt encountered finite draft-validation errors and then a
free-account quota. At this snapshot, positive Claude completion remained pending.
This snapshot makes no Claude Desktop or successful autonomous-authoring claim.
Publication remains subject to completion of the remaining host checks and passing
CI for the exact release commit; subsequent outcomes belong in the release notes.

## Reproduction outline

From a clean candidate checkout, use its own environment:

```sh
uv sync --frozen --all-extras --dev
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
uv run python scripts/audit_release.py --archive dist/regulatory-harvest-skill.zip --json
```

Build the ZIP twice and compare its bytes. Validate a clean extraction with the
skill validators. Install the wheel into a new environment outside the checkout;
run the copied `examples/offline` workflow and the licensed
`tests/fixtures/legalbench-mini` calculation as described by CI. Exercise actual
installed-host `prepare` and `finalize`, inspect the generated receipts, and retain
failed-source and scope limitations. Do not substitute this outline for the fuller
[release checklist](../release-checklist.md).

## Publication boundaries

The owner selected an explicitly experimental release. The external owner-marker
inventory was unavailable, not passed; private-matter rollout validation remains
deferred. Private calibration and operational evidence are not distributed here.
No PyPI publication or stable-release claim is made.

The intermittent saved-run verification refusal remains unresolved. Do not bypass
verification or deliver an unverified report; later successful verification is not
proof of a repair. Protocol 2.1 remains the default, and the provisional 0.70
review-ready floor is unchanged. Qualified-attorney review remains required.
