# Analysis Draft Schema

Write `analysis-draft.json` as one strict JSON object. Unknown fields are rejected. A new prepared matter has three layers:

1. `issues`, `findings`, and `gaps` form the evidence and validation layer.
2. `coverage_contract_version`, `unit_reviews`, `lead_dispositions_v2`, `rule_atoms`, and `rule_relationships` form the internal target-disposition ledger and atomic rule graph.
3. `brief` forms the attorney-facing presentation layer.

The brief may reorganize supported findings for clarity, but it may not invent or omit them. The attorney never edits the atom graph. The ledger and graph are internal and are not rendered as a database view in the report.

## Complete shape

Copy [analysis-draft.template.json](../assets/analysis-draft.template.json) and replace every `__REPLACE__` sentinel. A V2 draft has this top-level shape:

```json
{
  "coverage_contract_version": "proposition-coverage-v2",
  "issues": [],
  "findings": [],
  "gaps": [],
  "lead_reviews": [],
  "proposition_coverage": [],
  "unit_reviews": [],
  "lead_dispositions_v2": [],
  "rule_atoms": [],
  "rule_relationships": [],
  "brief": {}
}
```

Leave legacy `proposition_coverage` and `lead_reviews` empty for V2. Explicit V1 and historical no-key drafts are replay-only compatibility inputs and must not be relabeled or migrated during finalization.

## Evidence layer

- IDs must be nonblank and unique within their category. Use stable descriptive slugs.
- Every finding's `issue_id` must identify a listed issue.
- `category` must be `status`, `scope`, `requirements`, `enforcement`, `deadlines`, `implementation`, or `other`.
- Every issue and gap needs the category that matches the question it answers or leaves unresolved.
- `presentation_role` is optional compatibility metadata. It does not determine report structure.
- `severity` must be `critical`, `high`, `medium`, `low`, or `info` and means research priority, not client risk.
- Claim `kind` must be `source_supported` or `analysis`.
- `confidence`, when used, ranges from `0.0` to `1.0` and never changes validation.
- Copy `source_id` exactly from `agent-dossier.json` and `quote` exactly from its `normalized_text`.
- When one sentence states independent duties joined by a conjunction, split the claim texts but reuse an exact quotation that actually appears in `normalized_text`; never add punctuation to manufacture a clause-sized quote.
- Omit `occurrence` when the quote occurs once. Use a one-based occurrence only when identical text occurs more than once.
- Use an empty `proposed_citations` list for analysis claims.
- Set `enforcement_roles` to a unique list containing `trigger`, `consequence`, both, or neither. Use `trigger` only for the supported condition that activates enforcement and `consequence` only for the resulting route, order, remedy, penalty, or consequence.
- Tie gap `source_ids` to known dossier sources when applicable.

Keep one material legal proposition per source-supported claim. Split claims when clauses require different authorities, effective dates, or applicability assumptions. Use findings to group claims that share an issue, jurisdiction, authority, and practical implication.

For each of `status`, `scope`, `requirements`, `enforcement`, `deadlines`, and `implementation`, provide a source-supported finding or categorized plain-English gap. This coverage contract does not force six report sections.

## V2 target review and atomic rule graph

Read every successful source in full before attaching exact quotations. `source_unit_inventory` and `evidence_inventory` are indexes, not substitutes for reading and not legal conclusions. Broad unit mapping is insufficient: complete all nine dimensions for every unit, disposition every lead, and then atomize every independently operative proposition.

### Unit reviews

Create exactly one `unit_reviews` row per source unit. Every row contains `unit_id` and all nine dimensions:

1. `authority_status_timing`
2. `actors_scope_activities`
3. `definitions_categories`
4. `duties_rights_prohibitions`
5. `triggers_thresholds`
6. `conditions_exceptions_defenses`
7. `deadlines_transitions`
8. `enforcement_remedies_consequences`
9. `cross_references_dependencies`

Each dimension has exactly one disposition:

| Disposition | Payload |
|---|---|
| `mapped` | Nonempty, unique `atom_ids`; no gaps or rationale. |
| `gap` | Nonempty, unique `gap_codes`; no atoms or rationale. |
| `not_present` | No payload. Use only when the unit states nothing in that dimension. |
| `not_material` | Concrete nonblank `rationale`; no atoms or gaps. |

Use `gap` when responsive text or an expected dimension cannot be established. `not_present` and `not_material` are not substitutes for a genuine gap.
When one composite dimension contains both a supported proposition and a material unresolved component, map the supported atom through the other applicable dimension and use `gap` here for the unresolved component; do not let supported timing erase an unresolved authority-status question.

### Lead dispositions

Create exactly one `lead_dispositions_v2` row per provision lead, including nonpriority and navigation leads:

| Disposition | Payload |
|---|---|
| `mapped` | Nonempty, unique `atom_ids`. |
| `gap` | Nonempty, unique `gap_codes`. |
| `not_material` | Concrete nonblank `rationale`. |

The provision-lead inventory is not the coverage table. A mapped lead must resolve to an atom assigned to that lead; a gap must be category- and source-compatible with the lead.

### Rule atoms

Independent actions become distinct atoms. Do not encode multiple duties, rights, prohibitions, exceptions, deadlines, triggers, routes, consequences, or definitions in a list-valued element. Every atom contains:

Keep an ordinary condition that activates a duty in that duty atom's scalar `trigger` element. Create a separate `enforcement_trigger` atom and `triggered_by` relationship only for a violation or condition that activates enforcement; do not relabel an ordinary duty trigger as an enforcement trigger.

| Field | Contract |
|---|---|
| `atom_id` | Required nonblank ID, unique across the draft. |
| `unit_ids`, `lead_ids` | Unique prepared targets; at least one target overall. |
| `category` | One issue category. |
| `proposition_type` | `status`, `definition`, `scope`, `right`, `duty`, `prohibition`, `exception`, `deadline`, `enforcement_trigger`, `enforcement_route`, `remedy`, `penalty`, `appeal`, `implementation`, or `other`. |
| `materiality` | `critical`, `material`, or `supporting`. |
| `elements` | All fourteen scalar element fields below. |
| `omission_rationale` | Concrete explanation of the legal distortion caused by omission. |

Every atom has exactly these elements: `actor`, `modality`, `operative_action`, `object`, `trigger`, `threshold`, `condition`, `exception`, `timing`, `authority`, `route`, `consequence`, `defined_term`, and `defined_meaning`.

| Element status | Payload |
|---|---|
| `stated` | Nonblank scalar `text` and nonempty, unique `claim_ids`; no gaps. |
| `not_established` | Nonempty, unique `gap_codes`; no text or claims. |
| `not_applicable` | No text, claims, or gaps. |

For every stated element, bind at least one exact source-supported claim whose resolved quotation span overlaps at least one assigned unit or lead. Across all stated elements, combined exact evidence must cover every assigned target. A genuine gap remains a gap; do not convert an unknown interval, threshold, actor, or route into supported text.

### Typed relationships

Each `rule_relationships` row contains a unique `relationship_id`, `relation_type`, `source_atom_id`, `target_atom_id`, and nonempty unique `claim_ids`. Self-links, unknown endpoints, duplicate IDs, duplicate edges, and cycles in acyclic relationship families are invalid.

| Relationship | Required direction |
|---|---|
| `qualifies` | qualifying atom -> qualified atom |
| `exception_to` | exception -> rule |
| `deadline_for` | deadline -> governed rule |
| `enforces` | enforcement route -> governed rule |
| `triggered_by` | enforcement trigger -> duty or prohibition; remedy or penalty -> enforcement trigger |
| `consequence_of` | remedy or penalty -> duty or prohibition |
| `appeals_from` | appeal -> appealed decision or route |
| `defines` | definition -> defined rule or category |

An exception, deadline, enforcement trigger, route, remedy, penalty, or appeal requires an appropriate relationship family. Bind each relationship to exact evidence from both endpoint source contexts. A cross-source relationship therefore needs evidence from both sources; evidence from only one endpoint is insufficient.

### Materiality challenge

A citation quote is not coverage. Before assigning `not_material` or drafting prose, compare each responsive source unit, provision lead, and exact citation quote against the claim and atomic graph. If an actor, duty, right, qualification, independence condition, location condition, threshold, deadline, enforcement authority, route, remedy, or consequence survives only in the quotation, map it to an atom or preserve a source-bound gap. A nearby claim or atom about the same topic is not a substitute for the independently operative element.

A concrete `not_material` rationale must identify one of these ordinary reasons in prose: navigation or publication metadata; exact duplication of a named mapped atom; outside the scoped question; nonoperative or superseded text; or evidentiary context that states no independent legal proposition. These reasons are authoring guidance, not a parsed enum or a schema change.

### Visible brief binding

Bind critical and material atoms and relationships to visible `legal_analysis` paragraphs, list items, or table rows using `claim_ids`, `atom_ids`, and `relationship_ids`. A visible relationship binding must include both endpoint atom IDs and a relationship claim. Related atoms may share natural prose when the unit preserves every operative actor, trigger, threshold, exception, timing rule, route, and consequence. Internal IDs never appear in rendered prose.

### Final graph-to-report omission pass

Trace (1) each responsive unit or lead to an atom or source-bound gap; (2) each citation quote to a narrowly stated source-supported claim; (3) each claim to the atom elements and relationships it states; (4) every critical or material atom to one visible legal-analysis binding; and (5) each visible binding into rendered report prose without losing material actors, conditions, authorities, or consequences during compression. Deterministic `completed` status proves schema, evidence, and binding consistency, but it does not excuse a substantively false `not_material` decision.

After authoring, challenge exceptions, thresholds, triggers, consequences, cross-references, status changes, dates, defenses, and source limitations. Finalization writes `coverage-review.json`; repair every finite diagnostic and rerun. Do not delete gaps or dismiss responsive targets to obtain a green result.

## Brief structure

Set `brief.structure_profile` to `regulatory-walk-v1`. `brief.executive_summary` and `brief.sections` must be nonempty. Section identifiers must be unique; every section must contain a block or subsection; subsection identifiers must be unique within their section.

Build a summary-first, matter-specific regulatory walk in regulation-centered, direct legal voice. Begin with supported legal analysis, not source-container narration. Put source sufficiency and currentness qualifications in a final Executive Summary `limitation` block or the rendered limitations section.

Every section has one `role`: `key_requirements`, `penalties_enforcement`, `implementation`, or `other`. Include exactly one of each canonical anchor, with these exact headings and relative order:

1. `Key Requirements` with role `key_requirements`.
2. `Penalties and Enforcement` with role `penalties_enforcement`.
3. `Implementation Workplan` with role `implementation`.

Every supported requirements finding appears in Key Requirements. Every supported enforcement finding appears in Penalties and Enforcement as supported trigger-and-consequence architecture. Key Requirements permits only `legal_analysis` and `limitation`; Implementation Workplan permits only `application`, `client_fact`, and `limitation`. When a legal category is unsupported, retain its canonical anchor with a `limitation` beginning `Not established:` and a matching categorized gap.

Build Key Requirements from each material `source_supported` claim under provision-centered headings. State a direct legal rule naming the regulated actor or rights holder, bind the supporting `claim_ids`, and keep exact quotations in `audit.md`. Build Implementation Workplan separately from each finding's `practical_implication`, analysis claims, client facts, assumptions, and gaps.

Other headings use role `other` and remain adaptive. Place status, applicability, actors, activities, definitions, thresholds, exclusions, exceptions, rights, defenses, deadlines, and transitions where the legal walk needs them while preserving canonical-anchor order. The renderer owns `Executive Summary`, `Bottom Line`, `Priority and Posture`, `Limitations and Open Questions`, `Sources Consulted`, and `Evidence and Validation Appendix`; do not use those as authored section titles.

## Brief blocks and evidence

Every block has one `kind` and `purpose`:

- `paragraph`: `text` plus optional block-level bindings.
- `bullet_list` or `numbered_list`: nonempty `items`; bindings belong on each item.
- `table`: at least two `columns` and nonempty `rows`; each row's `cells` match the column count and bindings belong on the row.

Allowed purposes are `legal_analysis`, `application`, `client_fact`, and `limitation`. Every legal-analysis unit must reference the source-supported claims it restates. Include owning `finding_ids` when useful. Application, client-fact, and limitation content may omit evidence only when it does not masquerade as a legal proposition.

In Penalties and Enforcement, every supported legal-analysis unit supplies nonempty `enforcement_trigger_claim_ids` and `enforcement_consequence_claim_ids`, both drawn from its `claim_ids` and from claims carrying matching `enforcement_roles`. One claim may fill both roles only when one supported proposition states the complete trigger-and-consequence rule.

Keep exact quotations out of the brief. The renderer adds concise source markers; exact quotations remain in `audit.md`.

## Output and repair boundary

`report.md` contains compact matter metadata, the Executive Summary, authored sections, consolidated limitations, nonempty source groups, and the attorney-review warning. `audit.md` contains the research question, provenance, exact quotations, gap codes, deterministic validation, review items, and run metadata. `coverage-review.json` records internal unit, lead, atom, relationship, evidence, and visibility results. Do not recreate those internal structures in the attorney report.

When the engine reports a quote, source, support, target, graph, evidence, gap, or visibility diagnostic, repair the named source identifier, exact quotation, claim, target disposition, atom, relationship, authored gap, or visible binding and rerun. Do not hand-calculate character offsets or bypass validation.
