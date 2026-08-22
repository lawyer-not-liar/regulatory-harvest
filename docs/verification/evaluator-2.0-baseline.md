# Evaluator 2.0 baseline

## Frozen protocol 1.3 comparison point

- Protocol 1.3 baseline commit: `83e27583159273480927ec35e82dd5e159d39b8f`.
- Core full-plus-portable evaluator surface: 21,148 lines.
- The six protocol 1.3 evaluator operation types are `admit_case`,
  `build_ledger`, `audit_ledger`, `repair_ledger`, `grade_report`, and
  `referee`.
- Protocol 1.3 permits two repair responses and contains one
  grading-referee loop.
- Protocol 1.3 LLM responses can originate mechanical fields including ledger
  and claim identifiers, walk order, relationship identifiers, fingerprints,
  hashes, score inputs and outputs, repair transactions, and replacement
  artifacts.

## Protocol 2.0 contract targets

- Four substantive operation types: `source_review`, `source_audit`,
  `source_referee`, `grade_report`.
- One mechanical repair response maximum per call.
- Zero grading-referee operations.
- Zero LLM-originated canonical IDs, order fields, fingerprints, hashes,
  scores, or transactions.
- Protocol 2.0 full-plus-portable implementation no larger than 12,689 lines,
  60% of the 1.3 core surface.
- Every inner LLM response model has at most eight top-level fields.

Protocol 1.3 artifacts and replay behavior remain frozen; protocol 2.0 is a
parallel contract surface and does not reinterpret historical runs.

## Post-implementation public comparison

| Measure | Protocol 1.3 baseline | Protocol 2.0 implementation |
| --- | ---: | ---: |
| Full-plus-portable evaluator surface | 21,148 lines | 5,431 lines |
| Substantive role operations | 6 | 4 |
| Fresh mechanical repairs per call | 2 | 1 |
| Grading-referee operations | 1 | 0 |
| LLM-authored canonical mechanical fields | present | 0 |

The implementation surface is 25.7% of the frozen baseline (5,431 / 21,148),
below the 12,689-line target. It comprises 3,488 full-module lines + 1,943 marked
portable-section lines. These are code-surface and contract
measures, not quality, benchmark, legal-correctness, or private-run performance
claims.

### Public synthetic mechanical-refusal probe

The public Protocol 2.0 malformed-response fixture deliberately submitted two
invalid synthetic envelopes; both were refused (2/2, 100%). No Protocol 1.3
refusal-rate execution was measured for this comparison. This is a safety-path
probe, not an operational refusal rate and not evidence about private prompts,
sources, responses, or report grading. The prior private evaluation stopped
mechanically before report grading.
