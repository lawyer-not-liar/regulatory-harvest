# Key Requirements and Penalties Report Structure Design

**Date:** 2026-08-11
**Status:** Approved for specification review

## Goal

Make every new Regulatory Harvest attorney report visibly walk through the
regulation's key requirements and its penalties and enforcement architecture.
Preserve the system's stronger citation, status, currentness, gap, and audit
controls.

## Evaluation signal

A private three-case formative comparison found equal source support and status
safety for Regulatory Harvest and the legacy analysis. The legacy analysis was
consistently more useful because its legal walk made requirements and penalties
easy to locate and understand. This design uses only that de-identified product
signal. No private report, source, matter identity, mapping, rating record, or
legacy text enters the public package.

## Approaches considered

### Prompt guidance only

Strengthen the authoring instructions but keep the schema and validator
unchanged. This is the smallest change, but the current prompt already requests
requirements, enforcement, remedies, and penalties. The evaluated reports
technically covered those categories without presenting the strong visible walk
the attorney needed. Prompt guidance alone is therefore insufficient.

### Heading-name validation

Require sections whose titles contain words such as `requirements`,
`enforcement`, or `penalties`. This avoids a model change but is brittle. It
cannot distinguish a dedicated legal section from an incidental mention, cannot
reliably enforce placement, and makes synonyms a validation loophole.

### Semantic section anchors with canonical headings

Add a backward-compatible structure profile and semantic roles for three report
anchors: `Key Requirements`, `Penalties and Enforcement`, and `Implementation
Workplan`. Use positive authoring guidance to compose the content and
deterministic validation to require the anchors, ordering, and category
placement. This is the approved approach.

## Report contract

Every new report using the structure profile contains exactly one section with
each of these canonical headings:

1. `Key Requirements`
2. `Penalties and Enforcement`
3. `Implementation Workplan`

`Key Requirements` appears before `Penalties and Enforcement`, and both appear
before `Implementation Workplan`. Status, scope, definitions, exceptions,
deadlines, and other matter-specific sections remain adaptive and may appear
where the legal analysis requires them.

The Executive Summary remains the only summary or conclusion section. This
change does not restore a separate Bottom Line.

## Key Requirements section

The section groups the regulation's supported substantive and procedural duties
into obligation families an attorney can scan. Depending on the authority, its
subsections may include:

- substantive duties and prohibitions;
- procedural duties and response steps;
- governance, documentation, recordkeeping, or reporting duties;
- exceptions, thresholds, and conditions that qualify an obligation.

Subsections are included only when supported or materially unresolved. The
author should prefer labeled bullets or short numbered elements for discrete
duties and prose for rule synthesis. Every supported finding categorized as
`requirements` must appear in this section, although a finding may also support
another section where repetition adds genuine analytical value.

## Penalties and Enforcement section

The section explains the consequence architecture rather than merely stating
that enforcement exists. When supported, it addresses:

- the triggering violation or condition;
- the corresponding penalty, remedy, loss of protection, or other consequence;
- the enforcing authority and enforcement route;
- administrative, civil, criminal, or judicial mechanisms;
- private rights, cure rights, defenses, limitations periods, and cooperation
  considerations.

When two or more distinct trigger-and-consequence pairs are supported, the
preferred form is a compact table. Otherwise, use concise prose or bullets.
Every supported finding categorized as `enforcement` must appear in this
section. Exact source markers remain attached through the existing
`finding_ids` mechanism.

## Explicit not-established state

Both canonical sections remain visible even when the retained evidence does not
establish the answer.

If a category has no supported finding, its section contains a limitation block
beginning with `Not established:` and states the missing legal information in
plain English. The corresponding categorized gap must exist in the canonical
bundle. The report must not infer a requirement, penalty, enforcement body,
private right, or remedy to fill the section.

If the evidence establishes part of a category, the section states the
supported law and identifies material unresolved facets. Canonical gaps remain
consolidated in `Limitations and Open Questions`, even when a short coverage
qualification also appears in the relevant section.

## Data model and compatibility

Add an optional attorney-brief structure profile with the value
`regulatory-walk-v1`. Add a semantic role to brief sections with the
values `key_requirements`, `penalties_enforcement`, `implementation`, and
`other`.

New analysis drafts produced under the current skill must use the structure
profile, and every section in a profiled brief must carry one of the roles. The
new-draft parser rejects an authored brief that omits the profile. Existing
terminal bundles without the profile remain valid and render under the prior
adaptive behavior because they load through the canonical bundle model rather
than the new-draft boundary. This preserves schema-version `1.0` compatibility
while making the stronger contract mandatory for newly authored reports.

For a profiled brief:

- each canonical role appears exactly once;
- each role uses its canonical heading;
- the three roles appear in the required order;
- supported requirement findings appear within `key_requirements`;
- supported enforcement findings appear within `penalties_enforcement`;
- a gap-only canonical section contains the explicit not-established state and
  the bundle contains a matching category gap.

The dependency-free portable runner implements the same model defaults,
validation rules, issue codes, paths, and messages as the full engine.

## Authoring and rendering

Update the universal skill, build prompt, draft reference, and example draft to
require the new structure profile. The authoring recipe should mirror the
legacy report's clarity without copying its factual content or treating it as
ground truth.

The deterministic renderer continues to render authored sections and validated
source markers. It does not synthesize legal requirements or penalties from raw
findings. The host author remains responsible for coherent legal explanation,
and the deterministic core remains responsible for structural, evidence, and
coverage checks.

## Validation failures

Use stable `BRIEF_*` errors for:

- a missing or duplicate canonical section role;
- a noncanonical heading for a canonical role;
- incorrect canonical-section order;
- a supported requirement or enforcement finding omitted from its canonical
  section;
- a gap-only canonical section without `Not established:` content or without a
  corresponding categorized gap.

Existing evidence-linkage, exact-quotation, source-framing, coverage, and
attorney-review validation remains unchanged.

## Testing

Add synthetic, public-safe fixtures covering:

- multiple supported requirements grouped under useful subsections;
- multiple violation-and-consequence pairs rendered as a table;
- a single supported enforcement consequence rendered as prose;
- gap-only requirements and gap-only penalties sections;
- partial findings plus material gaps;
- missing, duplicate, mislabeled, misordered, and misplaced sections;
- full-engine and portable-runner issue parity;
- prior bundles without the structure profile;
- clean rendering with no raw quotations, validation codes, or private data.

Run focused tests first, then the full test, lint, type, package, extracted-ZIP,
privacy, and offline verification suites.

## Non-goals

- Do not copy legacy claims, risk ratings, organization-specific application,
  or unsupported legal conclusions.
- Do not force all other report headings into a fixed template.
- Do not add a separate Bottom Line.
- Do not add storage, database, n8n, MCP, model-provider, or search-provider
  dependencies.
- Do not move private evaluator materials into the public worktree.
- Do not publish, push, merge, or contact an external service.

## Acceptance criteria

1. Every newly authored report visibly contains `Key Requirements`, `Penalties
   and Enforcement`, and `Implementation Workplan` in that order.
2. Supported requirements and enforcement findings appear in their respective
   canonical sections with validated source markers.
3. Missing evidence produces a visible `Not established:` statement and a
   matching canonical gap, not fabricated law.
4. The remainder of the legal walk stays matter-specific and summary-first.
5. Older unprofiled bundles remain loadable, valid, and renderable.
6. Full and portable implementations produce identical structural validation.
7. The self-contained Codex and Claude Desktop skill package remains one
   dependency-free release artifact.
8. Private comparison data remains outside the public package.

Results are AI Generated and may contain errors. Output must be validated by an
attorney before the attorney delivers legal advice.
