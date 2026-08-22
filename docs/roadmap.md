# Roadmap

## Simplified evaluator boundary: design complete, implementation in progress

The experimental beta demonstrated that deterministic evidence and integrity
checks are valuable, but also that the evaluation controller can demand too
much machine-perfect artifact construction from an LLM. The bounded private
evaluation stopped on ledger-audit mechanics before substantive grading. That
is an orchestration-design signal, not a substantive evaluation result.

The Protocol 2.0 design enforces this division of responsibility:

- The LLM supplies substantive judgments, legal classifications, omissions,
  relationships, and proposed corrections.
- The deterministic code constructs canonical artifacts, assigns identifiers,
  normalizes ordering, computes fingerprints, checks invariants, and seals the
  result.

The redesign should preserve exact-source verification, provenance, citation
resolution, write-free refusals, bounded retries, replay integrity, and
attorney-review limits. It should reduce evaluator-authored schema surface,
mechanical refusal rates, duplicated orchestration, and total maintenance cost.
No safety or evidence gate should survive merely because it is deterministic;
each gate must protect a named user or integrity risk.

The current implementation preserves the experimental-beta lesson: the prior
private evaluation stopped mechanically before report grading, so it is not
performance evidence. Public synthetic protocol tests exercise the bounded
controller only; no private end-to-end run is reported here. Completion requires
the separately governed readiness gate, without relaxing an unfavorable result,
hiding a gap, or asking the LLM to hand-author canonical storage structures.
