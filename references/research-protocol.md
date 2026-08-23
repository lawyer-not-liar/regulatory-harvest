# Research Protocol

Use this protocol for every Regulatory Harvest matter.

## 1. Establish the charter

Record:

- `matter_id`: a safe, stable slug.
- `question`: one concrete legal-research question.
- `jurisdictions`: every jurisdiction the answer purports to cover.
- `as_of`: the date through which authority should be current.
- `source_mode`: exactly `provided-only` or `web`.
- `context`: legally material facts, not a narrative dump.
- `excluded_topics`: issues intentionally outside scope.
- `output_instructions`: audience, desired emphasis, and deliverable constraints.
- `sources`: every file and URL sent to the deterministic collector.

Do not put secrets, model credentials, private database addresses, or internal service configuration in the charter.

## 2. Apply the mode boundary

### Provided-only

- Use only the source locations the user supplied.
- Do not search for additional authority.
- Do not assert comprehensive or current-law coverage unless the supplied set itself proves it.
- Add `CLOSED_UNIVERSE_CURRENTNESS_UNVERIFIED` when the answer depends on currentness that the supplied materials cannot establish.
- Add `CLOSED_UNIVERSE_SCOPE_LIMIT` when potentially relevant authority lies outside the supplied set.

### Web

Separate web research into two passes.

**Discovery pass**

- Search broadly for governing bodies, terminology, candidate authority, legislative or rulemaking history, implementation materials, and contrary or superseding authority.
- Use secondary sources to find citations and status questions, not to settle what binding law requires.
- Create a source matrix with one row per candidate: proposition sought, jurisdiction, authority level, status, version or date, canonical URL, source language, verification result, and conflicts.

**Verification pass**

- Open direct official government, legislature, court, regulator, or standards-body sources.
- Confirm the relevant text, issuer, jurisdiction, official citation, enactment or adoption status, effective date, amendments, repeal, supersession, stays, injunctions, and pending replacements.
- Replace discovery summaries with verified primary authority whenever accessible.
- Preserve the official URL in `canonical_url`, even when `location` is a local capture, and record `language`.
- Add failed direct URLs when the retrieval failure matters to the audit record. Record alternate official copies when the canonical source is blocked or exceeds retrieval limits.
- Do not treat web research as complete unless at least one primary authority was successfully retained. If none is available, preserve `PRIMARY_AUTHORITY_UNAVAILABLE` and stop short of a verified-law conclusion.

## 3. Build a useful source record

For every source, populate only supportable metadata:

| Field | Meaning |
|---|---|
| `location` | Local file path relative to the charter, or direct public HTTP(S) URL. |
| `canonical_url` | Direct public URL for the official or best provenance copy, with tracking parameters and fragments omitted when possible. |
| `title` | Official or displayed title. |
| `publisher` | Issuing legislature, court, agency, regulator, or publisher. |
| `jurisdiction` | Jurisdiction actually covered by this source. |
| `authority_type` | Statute, regulation, rule, order, case, guidance, bill, secondary article, or other accurate type. |
| `citation` | Conventional legal or official citation when known. |
| `effective_date` | Effective date stated by the authority; do not substitute publication date. |
| `supersession` | Concise amendment, repeal, pending-change, or supersession note. |
| `language` | Source language, preferably a stable code such as `en` or `ja`. |
| `source_quality` | `primary`, `secondary`, `unknown`, or `unusable`. |
| `source_role` | `official_primary`, `secondary`, or `commentary_analysis`, based on how the source functions in the briefing. |
| `license_assertion` | Known reuse status or `unknown`. |

Source-quality metadata is an assertion, not proof. Inspect the normalized source text before relying on it.

## 4. Inspect the dossier

After `prepare`, read each dossier source and check:

1. `fetch_status` is `succeeded` before using its text.
2. `normalized_text` contains the expected authority.
3. The source is not a CAPTCHA, bot challenge, access-denied response, search page, navigation page, empty shell, or unrelated redirect.
4. The cited provision is present in the retrieved version.
5. Metadata matches the text and official context.
6. Duplicates or alternate copies do not mask version differences.

If these checks fail, replace the source, downgrade its quality, or preserve the limitation as a gap.

## 5. Sweep provisions before hardening evidence

Generate expansively and verify conservatively. Read every successful source in full. The evidence inventory (`evidence_inventory`) and `source_unit_inventory` are indexes, not substitutes for that reading and not legal conclusions. For a `proposition-coverage-v1` matter, review every required source unit and every provision lead.

Use this sequence:

1. **Provision sweep:** map authority status, actors, scope, definitions, duties, prohibitions, exceptions, thresholds, deadlines, enforcement triggers and routes, remedies, penalties, appeals, and implementation before attaching exact quotations.
2. **Target review:** complete all nine dimensions for every source unit and disposition every lead, including navigation text and nonpriority leads. Broad unit mapping is insufficient.
3. **Atomic rule graph:** use `proposition-coverage-v2`; split independent actions and other independently operative propositions into distinct atoms, connect them with typed relationships, and preserve genuine source-tied gaps and reasoned nonmaterial dispositions.
4. **Materiality challenge:** A citation quote is not coverage. Before assigning `not_material` or drafting prose, compare each responsive source unit, provision lead, and exact citation quote against the claim and atomic graph. If an actor, duty, right, qualification, independence condition, location condition, threshold, deadline, enforcement authority, route, remedy, or consequence survives only in the quotation, map it to an atom or preserve a source-bound gap. A nearby claim or atom about the same topic is not a substitute for the independently operative element. A concrete `not_material` rationale must identify one of these ordinary reasons in prose: navigation or publication metadata; exact duplication of a named mapped atom; outside the scoped question; nonoperative or superseded text; or evidentiary context that states no independent legal proposition.
5. **Completeness challenge:** challenge exceptions, thresholds, triggers, consequences, cross-references, status changes, dates, defenses, and source limitations.
6. **Evidence hardening:** bind each stated atom element to exact evidence overlapping at least one assigned target, require combined element evidence to cover all assigned targets, and bind relationships to both endpoint source contexts.
7. **Synthesis and visible binding:** write natural report prose with supporting claim, atom, and relationship bindings. Related atoms may share natural prose when every operative qualification survives.
8. **Adversarial omission review:** run a final graph-to-report omission pass: trace (1) each responsive unit or lead to an atom or source-bound gap; (2) each citation quote to a narrowly stated source-supported claim; (3) each claim to the atom elements and relationships it states; (4) every critical or material atom to one visible legal-analysis binding; and (5) each visible binding into rendered report prose without losing material actors, conditions, authorities, or consequences during compression. Deterministic `completed` status proves schema, evidence, and binding consistency, but it does not excuse a substantively false `not_material` decision. Recheck loss-prone provisions against full normalized text and repair unit reviews, leads, atoms, relationships, claims, gaps, and visible bindings.
9. **Finalize and repair:** repair every finite diagnostic in `coverage-review.json`; deliver only after the receipt is `completed` and all three coverage and precision booleans are true.

A categorized gap does not by itself resolve responsive source text. The persisted ledger and graph are internal: the attorney never edits the atom graph, and it is not rendered as a database view in the report. Leave V2 `proposition_coverage` and `lead_reviews` empty; retain explicit V1 and no-key matters only for replay compatibility.

## 6. Separate propositions from analysis

Create one `source_supported` claim for each material legal proposition. Keep its text close enough to the authority that lexical support is meaningful. Propose exact quotations that directly support that proposition.

Create a separate `analysis` claim for:

- Cross-authority synthesis.
- Applicability assumptions.
- Practical implementation advice.
- Risk ranking.
- Comparisons or distinctions not stated by one source.
- Inferences from the source set.

Do not combine quoted law and uncited synthesis in one claim.

## 7. Establish status before obligations

Use a status-first branch for every potentially material measure:

1. Identify the exact instrument and official identifier.
2. Determine whether it is enacted, effective, pending, proposed, amended, repealed, expired, superseded, stayed, enjoined, guidance, or voluntary.
3. For a nonoperative or failed proposal, confirm the disposition against official history and stop treating its text as a legal duty.
4. Check that a similarly titled enacted measure is actually the same instrument before linking them.
5. Only then analyze scope, requirements, enforcement, deadlines, and implementation.

If no operative authority or source-supported legal finding can be established, do not finalize a blank or generic report. Report the search result and gaps to the user. Obtain explicit permission before providing separately labeled hypothetical issue-spotting, and do not describe it as validated regulatory research.

## 8. Make applicability assumptions explicit

Create an assumption matrix before drafting:

| Factor | Known fact | Assumption | Legal consequence | Open question |
|---|---|---|---|---|

Cover legally dispositive facts such as role, location, sector, thresholds, covered conduct, exclusions, exemptions, implementation stage, and relevant dates. Convert missing material facts into `FACTUAL_CONTEXT_REQUIRED` gaps. Do not state that a rule applies merely because its subject matter resembles the client's activity.

Before prose drafting, author every V2 unit review and lead disposition, then build the atomic rule graph from the full normalized text. A unit review must contain the nine named dimensions; a lead needs exactly one mapped, gap, or reasoned nonmaterial disposition. A unit may map multiple atoms, but that broad mapping does not replace atomization. Independently operative duties, rights, prohibitions, exceptions, deadlines, triggers, routes, consequences, definitions, and other rules require distinct atoms with scalar elements.

After drafting, perform coverage reconciliation. Trace every stated atom element to exact source-supported claims, every relationship to evidence from both endpoint source contexts, and every critical or material atom and relationship to a visible legal-analysis unit. Trace every `gap` disposition and `not_established` element to a category- and source-compatible authored gap. Preserve statutory categories and cross-references instead of substituting narrower or broader colloquial labels.

## 9. Handle non-English authority

- Retain the original official text and identify the source language.
- Quote original-language text exactly for citation verification.
- Identify whether the English rendering is official, supplied, machine-assisted, or prepared by the host.
- Put the English explanation in an `analysis` claim unless a verified official English text directly supports it.
- Keep original-language quotations in `audit.md`. The main attorney analysis must be intelligible in English and must surface translation uncertainty.

## 10. Record gaps affirmatively

Use concise uppercase codes. Common codes include:

- `AUTHORITY_CURRENTNESS_UNVERIFIED`
- `AUTHORITY_STATUS_AMBIGUOUS`
- `CONFLICTING_AUTHORITY`
- `JURISDICTION_UNCOVERED`
- `PRIMARY_AUTHORITY_UNAVAILABLE`
- `SOURCE_RETRIEVAL_FAILED`
- `CLOSED_UNIVERSE_CURRENTNESS_UNVERIFIED`
- `CLOSED_UNIVERSE_SCOPE_LIMIT`
- `FACTUAL_CONTEXT_REQUIRED`
- `EFFECTIVE_DATE_PENDING`
- `TRANSLATION_REVIEW_REQUIRED`

Tie a gap to source identifiers when applicable. Do not use a gap as a substitute for doing available research.

Assign every gap to `status`, `scope`, `requirements`, `enforcement`, `deadlines`, `implementation`, or `other`. Before finalization, confirm that each of the six required categories has a supported finding or a categorized gap. The engine adds a conservative not-established gap if the draft omits a category, but that safeguard does not replace substantive research.

## 11. Completion gate

Complete only when:

- At least one substantive finding addresses the scoped question.
- Every material legal proposition is source-supported with an exact resolved citation.
- Every source unit and provision lead has a valid V2 review or disposition.
- Every atom and relationship has valid exact evidence, source-tied gaps where needed, and visible binding when material.
- Analytical propositions are labeled analysis.
- The authored brief opens with a substantive Executive Summary, uses matter-specific sections, and includes every source-supported finding.
- The attorney report omits raw quotations, machine diagnostics, and run metadata; those remain available in `audit.md`.
- Jurisdictions and as-of date are visible.
- Conflicts, failures, and uncertainty remain visible.
- The terminal bundle is sealed.
- `validation-receipt.json` reports `valid: true` and `status: completed`.
- `evidence_precision_valid`, `proposition_coverage_valid`, and `provision_recall_valid` are all true.
- Attorney review is expressly required.
- The report contains usable English analysis, an outline tailored to the matter, and practical application where the evidence and known facts support it.
