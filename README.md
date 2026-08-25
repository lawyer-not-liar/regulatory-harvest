# Regulatory Harvest

> **Experimental beta (`v0.1.0-beta.8`).** Beta.8 gives every Protocol 2.2
> ordinary and contested grader a controller-issued report-passage allowlist.
> Each allowed value is an exact unique substring of the supplied report, with a
> whole-report fallback when no narrower allowed passage suffices; strict grade
> validation remains unchanged. The beta.7 private evaluation accepted all
> source-stage calls before pausing at a hidden report-passage interface defect.
> Beta.8 addresses that interface defect, but beta.8 has not yet earned a private
> `PASS`.
> No performance, benchmark, or report-quality claim is made.
> Results are AI Generated and may contain
> errors. Output must be validated by an attorney before the attorney delivers
> legal advice.

The GitHub prerelease label `v0.1.0-beta.8` packages project version `0.1.0`.
The beta suffix describes the release channel. This release builds on exact
merge commit `bc7714f8b4b613aa0e4556e374f66508278091a9`. Protocol 2.2 remains
opt-in and experimental; Protocol 2.1 remains the new-run default. No PyPI
distribution is published.

Regulatory Harvest is an installable research skill for attorneys. Ask a legal question in ordinary language, attach your sources or authorize current web research, and receive a cited Markdown briefing plus a machine-verifiable evidence bundle.

The same skill package is designed for Codex and Claude Desktop. It uses the host agent for research and legal analysis, then passes the work through a deterministic Python engine that normalizes sources, resolves exact quotations, validates citations, records gaps, and seals the result.

For new matters, the skill also performs an internal fail-closed provision sweep that dispositions every required source unit and provision lead before delivery. This adds no user setup while preserving the natural-language attorney briefing.

### Protocol 2.2 current evaluation behavior

Protocol 2.2 is explicit experimental behavior; Protocol 2.1 remains the new-run
default. Internal evaluator roles return bounded semantic drafts, and deterministic
code applies safe normalization only to mechanically provable equivalents before it
constructs a strict compiled response. Content quality remains a downstream question
for independent audit, refereeing, and grading. Source-review and source-audit
fragments add at most five items. After two invalid internal drafts, the driver
returns exit 6 with the exact request pending; a later compatible invocation can
resume it. Only `COMPLETED` and substantive INCONCLUSIVE are terminal Protocol 2.2
outcomes. Grader lanes are scored independently: differences in cited passages or
requirement-level grades remain visible in the sealed aggregates, while only a
difference in the scored outcome produces `GRADER_DISAGREEMENT`. This experimental
path makes no benchmark claim, and qualified-attorney validation remains required.

### Experimental stable evaluation baseline

The opt-in `evaluation-baseline-v1` protocol creates one report-blind,
source-derived baseline for later report revisions. Its role loop and these five
commands are attorney-hidden mechanics:

- `eval-baseline-init`
- `eval-baseline-next`
- `eval-baseline-submit-safe`
- `eval-baseline-status`
- `eval-baseline-verify`

Baseline identity binds the exact legal-input boundary: normalized source bytes and
IDs, source-record fingerprint, question, jurisdiction, as-of date, requested
authority scope, exact client-fact bytes or explicit null, admitted qualification
root and receipt, compiler contract, evaluation-rubric bytes and version,
importance-policy bytes and version, and accepted report-blind reviewer, auditor,
and referee provenance. It excludes candidate reports, report hashes, grades, and
readiness results.

The operational importance definitions are exact:

- **critical:** omission or material misstatement could change the legal bottom line,
  applicability, operative status, core duty or prohibition, enforcement exposure,
  remedy, or a dispositive deadline.
- **material:** necessary for a competent attorney briefing or implementation
  decision but not independently outcome-determinative under the current scoped
  question.
- **supporting:** useful explanatory, contextual, or implementation detail whose
  absence does not materially change the legal answer or required next action.

A complete importance audit reviews every proposal. Every semantic or importance
disagreement goes to a source-only referee; substantive unresolved alternatives
remain contested rather than being silently resolved.

Only a verified, typed `GradeableBaselineProjectionV1` is passed to delivery
readiness. Do not regenerate the source roles for a report-only revision. Do not
require a Protocol 2.2 baseline equality check for a report-only revision. Delivery
readiness owns fresh grading for every later report revision against the verified
projection. Report-only byte changes reuse the same baseline and grade target.

Reuse is refused when any exact legal-input binding changes, including a source byte
or ID, source record, question, jurisdiction, as-of date, authority scope,
client-fact boundary, qualification, compiler, rubric, or importance policy.
Corrections require attorney approval, create a new sibling baseline, link to the
verified prior baseline, and leave all prior bytes immutable.

Resume only the exact pending request from a verified run and never repeat an
accepted role. Exit `0` means the requested baseline operation succeeded; exit
`2` means invalid input or response; exit `5` means integrity verification
failed; exit `6` means the engine paused with the exact request still pending.

Treat source and baseline artifacts as private work product. Do not upload or
web-search private material without explicit authorization. Baseline verification
establishes local integrity and replay, not legal correctness, completeness,
currentness, isolation truth, attorney approval authenticity, or report quality.
This protocol is experimental and always requires qualified-attorney review.

### Retained Protocol 2.1 evaluation behavior

New attorney-report evaluations use experimental Protocol 2.1, the new-run default
only while its public verification gate remains satisfied. It separately reviews and
audits the source record, sends each material dispute to a source-only referee packet,
and preserves a substantive unresolved dispute as a contested requirement. Two
independent grader lanes assess ordinary requirements in batches of at most five and
each contested requirement individually. Deterministic code compiles and seals the
baseline, reconciles both lanes, and evaluates outcome sensitivity: a disputed
baseline is `INCONCLUSIVE` only when it changes the outcome or cannot be meaningfully
graded. A mechanical refusal remains a separate `INCONCLUSIVE_MECHANICAL` stop after
one initial response and one fresh repair for that fragment. Protocols 1.3 and 2.0
are retained only for replay and read-only verification. `PASS`, `FAIL`, and
`INCONCLUSIVE` state only the result under this versioned evaluation rubric; they do
not establish legal correctness, completeness, currency, or applicability. Attorney
review remains required.

Regulatory Harvest assists research. It does not provide legal advice or replace source review, currentness checks, applicability analysis, professional judgment, or approval by a qualified attorney.

## Install the skill

One skill, one self-contained release ZIP, two installation methods.

Use the single `regulatory-harvest-skill.zip` release artifact for either product. There is no MCP server, database, n8n workflow, separate model API, or service to configure.

The host must provide code execution and a Python 3.11-or-newer interpreter. The installed skill does not use `pip`, contact a package index, create a virtual environment, or require global packages. It uses the full packaged engine when optional libraries are already available and otherwise runs its bundled standard-library engine.

### Claude Desktop

1. Download `regulatory-harvest-skill.zip` from the project release.
2. Open **Customize → Skills** in Claude Desktop.
3. Select **+ → Create skill → Upload a skill**.
4. Upload the ZIP and enable Regulatory Harvest.

Claude requires its code-execution capability to be enabled for skills that run bundled scripts. See [Claude's custom-skill instructions](https://support.claude.com/en/articles/12512180-use-skills-in-claude).

### Codex

Ask Codex's built-in skill installer to install Regulatory Harvest from this GitHub repository, for example:

```text
$skill-installer Install the regulatory-harvest skill from this GitHub repository.
```

For a downloaded release, extract the ZIP and place its `regulatory-harvest` folder under `~/.agents/skills/`. Codex discovers user skills there and can invoke the skill explicitly as `$regulatory-harvest`. See [OpenAI's skill documentation](https://learn.chatgpt.com/docs/build-skills).

### Build the installable ZIP from a source checkout

Until a release artifact exists, a maintainer can build the same universal ZIP locally:

```bash
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
```

This is a packaging step for the maintainer, not part of the attorney workflow.

## Use it

Ask naturally. The skill selects one of two explicit source modes.

### Analyze only supplied sources

Attach or identify the files and say:

> Use Regulatory Harvest. Using only these materials, explain the California requirements that apply to this product as of August 6, 2026. Quote the controlling language, identify unresolved questions, and produce an attorney briefing.

The skill will not perform web discovery. If the supplied set cannot establish currentness or complete coverage, the report will say so.

### Research current public authority

Say:

> Use Regulatory Harvest. Research the current federal and California rules governing automated decisions in employment as of August 6, 2026. Prioritize primary authority, distinguish effective law from proposals and guidance, and produce a cited attorney briefing.

The skill uses the host's available web-research capability, preserves selected public sources, and records failed or inaccessible authority as gaps. It will not put confidential source contents or client facts into web queries without explicit authorization.

### Evaluate reports automatically

Attach the authority packet and the report or reports, then say:

> Evaluate these two anonymous regulatory reports against the supplied authority and give me the automatic result.

That one plain-language request starts and completes the automated journey. The
skill runs source review and source audit, then uses source-only referee packets for
material disputes. A substantive unresolved decision becomes a contested requirement
rather than a forced legal choice. The workflow uses two independent grader lanes to assess ordinary
requirements in bounded batches and contested requirements individually; deterministic
outcome sensitivity determines whether an unresolved baseline changes the result. It validates responses and integrity without opening a browser reviewer or asking you to score either report. `PASS`, `FAIL`, and `INCONCLUSIVE` are limited rubric outcomes,
not legal advice. The resulting requirement matrix walks the authority provision by
provision and shows what each report covered, misstated, or omitted.

Existing reports are treated as external artifacts and graded independently. Their matrices can be viewed side by side, but Regulatory Harvest does not manufacture a winner or tie from reports whose generating builds were not captured. A formal two-build comparison requires each report to be created through its own verified generation capsule against the same source and client-fact bytes.

## What you receive

The primary deliverable is `report.md`. Its H1 is the name of the regulation, without a generic `Attorney Briefing` prefix. It starts with a substantive Executive Summary, then visibly walks through `Key Requirements`, `Penalties and Enforcement`, and an `Implementation Workplan`. Key Requirements states the supported legal rules in clear paraphrase with concise source markers. Implementation Workplan contains the recommended operational response. Those three anchors always appear in that order. If the retained evidence does not establish requirements or enforcement, the corresponding section says `Not established:` and the unresolved question remains in the audit record instead of being filled with speculation.

The rest of the outline remains adaptive and matter-specific. Depending on the question, the report may add sections for status, coverage, definitions, exceptions, deadlines, application, or another subject that helps explain the authority. Unsupported optional sections are omitted. Paragraphs, lists, subsections, and tables are used only when they improve the attorney's understanding. The conclusion is not repeated in a separate Bottom Line.

The companion `audit.md` keeps the research mechanics out of the attorney work product. It contains the complete research question, detailed source provenance, exact quotations, gap codes, deterministic validation results, review items, and run metadata. Concise source markers in `report.md` link the analysis back to official authority without turning the report into a machine log.

The matter directory also contains:

```text
<matter>/
  research-charter.json       # scope and source-mode record
  request.json                # canonical engine request
  agent-dossier.json          # normalized sources and stable IDs
  analysis-draft.json         # host agent's strict proposed analysis
  coverage-review.json        # provision-lead disposition and recall gate
  validation-receipt.json     # terminal validation result
  inputs/                     # matter-local copies of supplied files
  runs/<matter-id>/
    bundle.json               # canonical, hash-sealed evidence record
    report.md                 # attorney-facing briefing
    audit.md                  # evidence, validation, and run audit
```

The skill creates and manages these files internally. The attorney does not need to edit JSON or run commands.

## What deterministic validation does—and does not—prove

The engine deliberately separates two questions. First, are the propositions the
report actually makes supported by the retained evidence? Second, did the report
address the material provisions surfaced across the full retained corpus? The
first is evidence precision; the second is provision recall. The workflow is to
**generate expansively, verify conservatively**: the host agent performs a broad
provision sweep and writes the legal narrative, then deterministic checks harden
the quotations, citations, and lead coverage without deciding what the law means.

The engine verifies:

- Source normalization, hashes, and provenance.
- A successful primary-authority gate for web-mode research.
- Exact quotation identity and character offsets.
- Citation and claim graph closure.
- Material source-supported claims without citations.
- Attorney-brief references, support, and complete finding coverage.
- The required Key Requirements, Penalties and Enforcement, and Implementation Workplan anchors, their order, category placement, and explicit not-established states.
- Transparent lexical-support warnings.
- Jurisdiction coverage and a finding-or-gap contract for status, scope, requirements, enforcement, deadlines, and implementation.
- Visible plain-English research limits with machine-readable gap codes retained for audit.
- Canonical bundle integrity.

New terminal research bundles use schema `1.1`, whose integrity hash covers every
current field. The verifier still accepts either authentic persisted schema-`1.0`
field shape by reconstructing its exact historical projection; it rejects mixed
legacy shapes and nondefault newer fields declared under `1.0` instead of omitting
them from the hash. Integrators can use `migrate_bundle_hash_contract` to verify and
rehash a retained `1.0` bundle into the current contract.

A green result does not prove that the analysis is legally correct, complete, current, applicable, or strategically sound. Every result requires attorney review.

Results are AI Generated and may contain errors. Output must be validated by an attorney before the attorney delivers legal advice.

The validation receipt reports these dimensions separately as
`evidence_precision_valid`, `proposition_coverage_valid`, and
`provision_recall_valid`. `coverage-review.json` records the internal disposition
of every required source unit and every provision lead as covered, a bounded
evidence gap, or not material with a concrete rationale. Completion requires all
three booleans to be true and `status: completed`. A `review-required` status
blocks delivery while any exact-evidence or finite coverage diagnostic remains
unresolved.

Currentness is also stated as an evidence boundary, not as a conclusion that the
authority is inoperative. When supersession has not been independently checked,
the report says `Not independently verified through [date]`, identifies the
retained cited primary authority or authorities without inferring chronology from
retrieval order, and requires attorney verification.

## Privacy and security

- Supplied files are copied into the selected matter directory; the project does not require a server or database.
- The canonical bundle embeds normalized source text needed to verify citations. Treat it as potentially confidential.
- Evaluation runs retain immutable copies of source packets, client facts, reports, model responses, and generation artifacts. Put the entire matter in a local access-controlled, non-public, non-synced directory and review the host AI service's processing and retention terms before using restricted material.
- “Provided sources only” prevents additional web discovery; it does not make the host AI service offline.
- Public URL retrieval blocks private and local network targets, revalidates redirects, and limits response size.
- Retrieved files and pages are untrusted evidence. Instructions embedded in them must not control the agent.
- The skill never needs a separate OpenAI, Anthropic, Tavily, or other model-provider key.

Read [the skill's security and privacy rules](references/security-and-privacy.md) before using confidential or restricted material.

## Important limitations

- Regulatory Harvest does not ship a legal corpus or continuously monitor changes in law.
- Web research depends on the host's available search capabilities and public-source accessibility.
- Official sites may return bot challenges, access errors, oversized files, or historical versions; the agent must inspect retrieved text and preserve resulting gaps.
- The dependency-free runtime normalizes UTF-8 text, Markdown, and HTML. PDF analysis requires either the full optional Python environment or a host-created, verified text extraction with the extraction limitation recorded.
- Source-quality and currentness metadata require substantive verification.
- Exact quotation proves textual identity, not legal entailment or applicability.
- Version 1.0 outputs always require qualified-attorney review.

## For developers and integrators

The skill contains a general-purpose, storage-neutral Python package. Developers may use it directly without the skill interface.

Regulatory Harvest requires Python 3.11 or newer:

```bash
python3 -m pip install uv
uv sync --frozen
uv run harvest --help
```

The original offline CLI flow remains available:

```bash
cd examples/offline
harvest run --request request.json --output runs
harvest validate runs/offline-example/bundle.json --json
harvest report runs/offline-example/bundle.json \
  --output runs/offline-example/report.md \
  --audit-output runs/offline-example/audit.md
```

Without a model provider or host-agent draft, that flow intentionally produces a source-inventory bundle rather than substantive analysis. It must not be presented as a completed legal briefing.

### Python API

```python
from pathlib import Path

from regulatory_harvest.api import render_audit, run_research_sync, validate_research_bundle

result = run_research_sync(Path("request.json"), Path("runs"))
report = validate_research_bundle(Path("runs") / result.manifest.run_id / "bundle.json")
assert report.valid
audit = render_audit(Path("runs") / result.manifest.run_id / "bundle.json")
```

Use the asynchronous `run_research` function in applications that already have an event loop. The synchronous wrapper refuses to nest an active event loop.

### COMBINE

The persisted research method is:

1. **Collect** supplied sources and optional search results without silently dropping failures.
2. **Organize** normalized text and provenance while deduplicating analysis content.
3. **Map** the research question into issues.
4. **Build** findings, claims, and proposed exact quotations.
5. **Inspect** hashes, citation closure, quote spans, support signals, and jurisdiction coverage.
6. **Note** gaps, source failures, invalid evidence, and attorney-review items.
7. **Export** the bundle, attorney report, evidence audit, manifest, and checkpoints.

The engine checkpoints every stage and resumes without repeating completed collection work.

### Optional integrations

The [cite/OpenContracts adapter](docs/integrations/cite.md) exchanges evidence through documented public interfaces. The [LegalBench-RAG evaluator](docs/evaluation.md) scores exact-character retrieval over a separately obtained dataset and does not redistribute benchmark data. Neither is required by the skill.

Reference OpenAI Responses API and Tavily Search adapters remain available for developers who choose to integrate the Python package directly. See [provider documentation](docs/providers.md). They are not part of the attorney-facing skill workflow.

### Automated evaluation operator contract

#### Protocol 2.2 current evaluator contract

Protocol 2.2 is explicit experimental behavior; Protocol 2.1 remains the new-run
default. An internal role supplies only a bounded semantic draft. Deterministic code
performs safe normalization only when equivalence is mechanically provable, creates
the strict compiled response, and leaves content quality to source audit, refereeing,
and grading. Source-review and source-audit fragments contain at most five new items.
Two invalid internal drafts return exit 6 with the exact request pending and
resumable; resume continues the same verified run without repeating accepted work.
Protocol 2.2 terminal outcomes are `COMPLETED` or substantive INCONCLUSIVE.
Protocols 1.3, 2.0, and 2.1 remain retained behavior, not mutable Protocol 2.2 runs.
There is no benchmark claim, and qualified-attorney validation remains required.

#### Retained Protocol 2.1 operator reference

The universal skill keeps the Protocol 2.1 fragmented role loop internal. A refused
response is write-free and discarded; for every fragment there is one initial
response and at most one fresh mechanical repair. A second mechanical refusal stops
as `INCONCLUSIVE_MECHANICAL`, never as substantive uncertainty. Accepted `FAIL` and
`INCONCLUSIVE` results are substantive outcomes, not retry triggers. The current
request supplies the role-specific inner schema. The evaluator returns only that
inner payload; the controller supplies truthful provider/model/isolation metadata
and the runner constructs the canonical outer envelope. The public v2.1 response
template is a compatibility reference for full-envelope callers.

## Development and contribution status

Regulatory Harvest is not accepting external contributions, pull requests,
issues, or feature requests during the experimental beta. The public repository
is provided for inspection, installation, and evaluation. Security reports must
use the private process in [SECURITY.md](SECURITY.md).

The commands below are maintainer development checks:

```bash
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
python3 scripts/build_skill.py --output dist/regulatory-harvest-skill.zip
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current closed-contribution
policy. Maintainers must also follow [CLEAN_ROOM.md](CLEAN_ROOM.md) and
[SECURITY.md](SECURITY.md). Tests and examples may use only synthetic or clearly
redistributable material.

## License

Regulatory Harvest is licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
