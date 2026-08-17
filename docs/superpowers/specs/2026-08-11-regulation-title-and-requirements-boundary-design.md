# Regulation Title and Requirements Boundary Design

**Date:** 2026-08-11
**Status:** Approved

## Goal

Make every new Regulatory Harvest report identify the regulation in its title and
present Key Requirements as a faithful attorney-facing account of the law. Keep
operational recommendations in Implementation Workplan, preserve exact quotations
in the audit, and retain the improved narrative and enforcement treatment.

## Evaluation signal

A private formative evaluation found that the underlying source support and legal
status treatment were strong, but the attorney-facing Key Requirements section
often converted supported legal propositions into operational instructions. The
same evaluation exposed a generic title fallback when a new matter omitted its
matter title.

Only these abstract product findings inform this design. No private source,
matter identity, report text, rating record, answer-key mapping, or client fact
enters the public package.

## Approaches considered

### Prompt guidance only

Revise the prose instructions and examples without changing validation. This is
small, but earlier guidance already requested direct legal voice and distinct
requirements and implementation sections. It did not prevent action-plan language
from appearing in Key Requirements.

### Semantic boundary with positive authoring recipe

Require a concrete regulation title for every newly profiled brief. Define Key
Requirements as legal analysis drawn from source-supported requirements claims,
and define Implementation Workplan as application content drawn from analysis and
practical implications. Enforce the content-purpose boundary deterministically,
while leaving substantive legal synthesis to the host model. This is the approved
approach.

### Structured obligation records

Add a new rigid data model with separate actor, trigger, duty, exception, timing,
and citation fields for every obligation. This would be highly enforceable, but it
would expand the public schema and risk producing mechanical reports. It is not
needed unless the approved approach fails a later evaluation.

## Report title contract

Every newly authored `regulatory-walk-v1` brief must have a nonblank
`request.matter_title`. The host derives that title during scoping from the
governing regulation's official or established common name and includes a familiar
acronym when useful.

The report heading is the matter title itself. Examples include:

- `# Employment Rights Act 1996`
- `# California Consumer Privacy Act (CCPA)`
- `# EU AI Act`

Do not prefix the title with `Attorney Briefing`, `Attorney Research Briefing`, or
another generic document label. The audit remains titled
`<matter title>: Evidence and Validation Audit`.

If the requested authority is ambiguous, the host resolves the authority during
scoping rather than inventing a title. A newly profiled brief without a matter
title cannot complete validation. Existing unprofiled terminal bundles retain the
current generic fallback for backward-compatible rendering.

## Key Requirements content contract

Key Requirements is a legal-rule section. It answers what the regulation requires,
prohibits, permits, or gives a person the right to demand. It does not tell the
client what project to run.

Compose the section from each requirements finding's `source_supported` claims,
not from its `practical_implication` or `analysis` claims. For every material
requirements claim:

1. State the regulated actor or rights holder.
2. State the duty, prohibition, permission, or right.
3. State the trigger, threshold, or condition when material.
4. State the deadline, exception, or qualification when material.
5. Attach the supporting finding identifier so the renderer provides the concise
   source marker.

Use accurate legal paraphrases with pinpoint source markers in the report. Keep
the exact source-language quotation in the separate audit artifact.

Group the resulting rules into provision-centered obligation families only after
the individual legal propositions have been accounted for. Use noun-phrase or
legal-topic headings such as:

- `Written Employment Particulars`
- `Notice at Collection and Use Limitations`
- `Deletion, Correction, and Access Rights`
- `Distance Contracts and Withdrawal Rights`

Do not use operational headings such as `Establish Coverage`, `Control
Collection`, `Make Rights Executable`, or `Build the Compliance Program`.

Within Key Requirements, use only blocks whose purpose is `legal_analysis` or
`limitation`. The rule explanation may use prose, bullets, or a compact table when
that form serves the legal analysis. Numbered lists are reserved for a legal test
or a sequence imposed by the authority, not a recommended implementation order.

When the source set does not establish a requirements category, retain the
existing `Not established:` limitation and matching gap behavior.

## Implementation Workplan content contract

Implementation Workplan converts the legal analysis into recommended action. Its
source material is the findings' `practical_implication` text, analysis claims,
client facts, assumptions, and identified gaps.

This section may contain `application`, `client_fact`, or `limitation` blocks. It
does not contain `legal_analysis` blocks. Legal propositions needed to explain an
action remain in the earlier legal walk and may be referenced through finding
identifiers without being restated as a second requirements section.

Typical workplan verbs include `assess`, `inventory`, `map`, `configure`, `test`,
`document`, `train`, `monitor`, and `verify`. Their presence here is intentional.

## Authoring data flow

The host follows this sequence:

1. Scope the named authority and set `matter_title` in the research charter.
2. Perform the full provision sweep and create evidence-layer findings.
3. For each requirements finding, enumerate its source-supported legal claims.
4. Convert those claims into minimally paraphrased legal-rule units for Key
   Requirements, then group the units under provision-centered headings.
5. Build the remaining legal walk, including Penalties and Enforcement.
6. Convert practical implications, analysis, factual assumptions, and gaps into
   the separate Implementation Workplan.
7. Finalize through deterministic evidence, structure, and purpose validation.

The deterministic engine does not generate legal prose and does not infer duties
from source text. It verifies that the host kept the two presentation purposes
separate and linked legal propositions to supported findings.

## Validation

For a `regulatory-walk-v1` brief, add stable validation errors for:

- `BRIEF_MATTER_TITLE_MISSING` when `request.matter_title` is absent;
- `BRIEF_KEY_REQUIREMENTS_PURPOSE_INVALID` for an `application` or `client_fact`
  unit anywhere inside Key Requirements;
- `BRIEF_IMPLEMENTATION_PURPOSE_INVALID` for a `legal_analysis` unit anywhere
  inside Implementation Workplan.

Apply the checks recursively to section blocks and subsection blocks. Match the
issue code, path, message, and related identifiers in the full engine and the
dependency-free portable runner.

Do not add deterministic verb matching or attempt to decide legal sufficiency by
keyword. Provision-centered headings and direct rule syntax remain model-led and
are controlled through the positive recipe, corrected examples, and evaluation.

## Files and surfaces

Implementation will update the narrow surfaces that own this behavior:

- universal skill authoring instructions;
- draft-schema reference and public-safe draft template;
- build prompt used by the library path;
- full and portable bundle validation;
- report and audit title tests;
- private evaluator charter materialization for future rounds only.

The installed Codex and Claude Desktop package will be rebuilt from the same
universal source only after verification. The completed private evaluation remains
immutable.

## Testing

Begin with red tests that reproduce the observed defects:

- a profiled brief with no matter title currently renders the generic fallback;
- Key Requirements currently accepts `application` content;
- Implementation Workplan currently accepts `legal_analysis` content;
- the current public-safe schema example places implementation inside Key
  Requirements.

Then verify:

- a named regulation renders as the exact H1 in both full and portable paths;
- old unprofiled bundles remain renderable;
- legal-analysis and limitation blocks pass in Key Requirements;
- application, client-fact, and limitation blocks pass in Implementation
  Workplan;
- invalid cross-purpose content produces full and portable issue parity;
- the package contains the corrected positive recipe and example;
- the full test, lint, type, package, extracted-package, privacy, and offline
  suites pass.

After implementation, run a fresh private blind comparison. Do not alter or reuse
the completed round. The next evaluation should specifically assess title quality,
requirements depth and fidelity, separation from implementation, narrative read,
and penalties treatment.

## Non-goals

- Do not add verbatim statutory quotations to the attorney-facing report.
- Do not add a rigid obligation-record schema in this iteration.
- Do not change the successful Penalties and Enforcement treatment.
- Do not add a separate Bottom Line.
- Do not weaken exact-evidence, currentness, gap, or attorney-review controls.
- Do not add storage, database, n8n, MCP, model-provider, or search-provider
  dependencies.
- Do not move private evaluator artifacts into the public worktree.
- Do not publish, push, merge, or contact an external service.

## Acceptance criteria

1. Every newly profiled report uses the named regulation or matter as its H1.
2. Key Requirements presents supported legal rules rather than recommended work.
3. Each material requirements claim is accounted for before rules are grouped.
4. Exact quotations remain in the audit; the report uses accurate paraphrases and
   concise source markers.
5. Implementation Workplan contains the operational recommendations and does not
   duplicate the legal-rule section.
6. Full and portable validators enforce the purpose boundary identically.
7. Existing unprofiled bundles remain compatible.
8. The universal skill remains one dependency-free package for Codex and Claude
   Desktop.
9. Private evaluation evidence remains local and unpublished.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.
