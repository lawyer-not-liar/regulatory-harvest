# Authority and Currentness

Read this reference for `web` mode or whenever the supplied sources purport to establish current law.

## Authority hierarchy

Prefer the most direct official version available:

1. Constitutions and enacted statutes.
2. Promulgated regulations and formally adopted rules.
3. Controlling judicial decisions and binding administrative orders.
4. Official agency interpretations, enforcement materials, and guidance, labeled according to their legal effect.
5. Legislative history, proposed rules, bills, and pending amendments, clearly labeled nonfinal.
6. Treatises, law-review material, practitioner commentary, vendor summaries, and journalism as secondary.

Hierarchy alone does not establish applicability. Check jurisdiction, issuing body's authority, effective date, covered persons, covered conduct, exclusions, exemptions, preemption, and procedural posture.

## Status vocabulary

Use precise labels:

- **Enacted:** Passed and signed or otherwise became law; may not yet be effective.
- **Effective:** Legally operative on the charter's as-of date.
- **Pending effective date:** Enacted but not yet operative.
- **Proposed:** Not final law.
- **Amended:** Later official text changes an earlier provision.
- **Repealed or expired:** No longer operative except for historical or transition issues.
- **Superseded:** Replaced by later authority or version.
- **Stayed or enjoined:** Effect limited by a current judicial or administrative order.
- **Guidance:** Official explanation whose binding force must be assessed separately.
- **Voluntary standard:** Useful practice material, not law unless incorporated or contractually adopted.

Do not collapse these labels into “current.”

Use a status-first analysis. A source's topic, title, bill number, or presence on an official site does not establish that it is operative law.

## Official provenance inference

The deterministic collector may classify an otherwise unknown source as primary when its canonical URL is on `legislation.gov.uk`, `eur-lex.europa.eu`, or `fedlex.admin.ch` and its authority type identifies a legal instrument, adjudication, or official guidance. Subdomains are accepted; lookalike suffixes are not. An explicit primary, secondary, or unusable classification takes precedence.

This inference concerns source provenance only. Official publication does not establish currentness, operative status, applicability, or completeness. Complete the currentness checklist and preserve a status or currentness gap whenever those questions remain unresolved.

## Currentness checklist

For each material authority:

1. Identify the official publisher and version date.
2. Confirm the relevant section or provision exists in the retrieved text.
3. Check amendments, repeal notes, delayed effective dates, transition provisions, and pending replacements.
4. Check later controlling decisions, stays, injunctions, waivers, or agency action when material.
5. Distinguish the date of enactment, publication, retrieval, and legal effect.
6. Record the result in `effective_date` and `supersession` without overstating certainty.

For a nonoperative measure, failed proposal, vetoed bill, withdrawn rule, expired provision, or superseded version, verify the disposition against official history. Do not connect it to a different enacted measure merely because names, topics, or summaries overlap.

If the check cannot be completed, add an explicit currentness gap.

## Primary versus secondary use

Use secondary sources to:

- Discover terminology and citations.
- Identify amendment or litigation history.
- Compare implementation approaches.
- Explain technical context.

Do not use a secondary source as the sole support for what binding primary authority requires when the primary text is reasonably accessible. If it is not accessible, preserve both the secondary source and a `PRIMARY_AUTHORITY_UNAVAILABLE` gap.

## Negative conclusions

Absence of located authority is not proof that no authority exists. Before stating that no rule was identified:

- Search using role-specific and sector-specific terminology.
- Check state and local law where relevant.
- Check adjacent regimes such as consumer protection, employment, credit, privacy, health, insurance, procurement, and professional regulation.
- State the search scope and phrase the conclusion as a research result, not a universal fact.
- Add a gap describing the residual uncertainty.

## Version traps

Watch for:

- Historical code pages returned without a clear version marker.
- Bills displayed beside enacted law.
- Agency summaries that lag final rules.
- Unofficial compilations missing amendments.
- Search-result snippets combining versions.
- Direct links that redirect to bot challenges or access pages.
- PDFs too large for the collector.
- Regulations incorporated by reference.
- Court opinions modified, withdrawn, depublished, or under review.

Seek an alternate official copy or record the limitation. Never treat an interstitial page as primary authority merely because its URL belongs to an official domain.
